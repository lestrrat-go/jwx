#!perl
use strict;
use File::Temp;

# Accept a list of filenames, and process them
# if any of them has a diff, commit it

# Use GITHUB_REF, but if the ref is develop/v\d, then use v\d
my $link_ref = $ENV{GITHUB_REF};
if ($link_ref =~ /^develop\/(v\d+)$/) {
    $link_ref = $1;
}

my @files = @ARGV;
my @has_diff;
for my $filename (@files) {
    open(my $src, '<', $filename) or die $!;

    my $output = File::Temp->new(SUFFIX => '.md');
    my $skip_until_end;
    for my $line (<$src>) {
        if ($line =~ /^<!-- END INCLUDE -->$/) {
            $skip_until_end = 0;
        } elsif ($skip_until_end) {
            next;
        }
        if ($line !~ /(^<!-- INCLUDE\(([^\),]+)(?:,([^\)]+))?\) -->)$/) {
            $output->print($line);
            next;
        }
        $output->print("$1\n");
    
        my $include_filename = $2;
        my $options = $3;
    
        $output->print("```go\n");
        my $content = do {
            open(my $file, '<', $include_filename) or die "failed to include file $include_filename from source file $filename: $!";
            local $/;
            <$file>;
        };
        $content =~ s{^(\t+)}{"  " x length($1)}gsme;
        $output->print($content);
        $output->print("```\n");

        $output->print("source: [$include_filename](https://github.com/lestrrat-go/jwx/blob/$link_ref/$include_filename)\n");
    
        # now we need to skip copying until the end of INCLUDE
        $skip_until_end = 1;
    }
    $output->close();
    close($src);

    if (!$ENV{AUTODOC_DRYRUN}) {
        rename $output->filename, $filename or die $!;
        my $diff = `git diff $filename`;
        if ($diff) {
            push @has_diff, $filename;
        }
    }
}

if (!$ENV{AUTODOC_DRYRUN}) {
    if (@has_diff) {
        # Write multi-line commit message in a file
        my $commit_message_file = File::Temp->new(SUFFIX => '.txt');
        print $commit_message_file "autodoc updates\n\n";
        print "  - $_\n" for @has_diff;
        $commit_message_file->close();
        system("git", "remote", "set-url", "origin", "https://github-actions:$ENV{GITHUB_TOKEN}\@github.com/$ENV{GITHUB_REPOSITORY}") == 0 or die $!;
        system("git", "config", "--global", "user.name", "$ENV{GITHUB_ACTOR}") == 0 or die $!;
        system("git", "config", "--global", "user.email", "$ENV{GITHUB_ACTOR}\@users.noreply.github.com") == 0 or die $!;
        system("git", "switch", "-c", "autodoc-pr-$ENV{GITHUB_HEAD_REF}") == 0 or die $!;
        system("git", "commit", "-F", $commit_message_file->filename, @files) == 0 or die $!;
        system("git", "push", "origin", "HEAD:autodoc-pr-$ENV{GITHUB_HEAD_REF}") == 0 or die $!;
        system("gh", "pr", "create", "--fill") == 0 or die $!;
    }
}
