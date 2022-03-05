#!perl
use strict;
use File::Temp;

# Accept a list of filenames, and process them
# if any of them has a diff, commit it

my @files = @ARGV;
my $has_diff = 0;
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
            open(my $file, '<', $include_filename) or die $!;
            local $/;
            <$file>;
        };
        $content =~ s{^(\t+)}{"  " x length($1)}gsme;
        $output->print($content);
        $output->print("```\n");
        $output->print("source: [$include_filename](https://github.com/lestrrat-go/jwx/blob/$ENV{GITHUB_REF}/$include_filename)\n");
    
        # now we need to skip copying until the end of INCLUDE
        $skip_until_end = 1;
    }
    $output->close();
    close($src);

    rename $output->filename, $filename or die $!;

    if (!$has_diff) {
        my $diff = `git diff $filename`;
        if ($diff) {
            $has_diff = 1;
        }
    }
}

if ($has_diff) {
    system("git", "remote", "set-url", "origin", "https://github-actions:$ENV{GITHUB_TOKEN}\@github.com/$ENV{GITHUB_REPOSITORY}") == 0 or die $!;
    system("git", "config", "--global", "user.name", "$ENV{GITHUB_ACTOR}") == 0 or die $!;
    system("git", "config", "--global", "user.email", "$ENV{GITHUB_ACTOR}\@users.noreply.github.com") == 0 or die $!;
    system("git", "commit", "-m", "autodoc updates", @files) == 0 or die $!;
    system("git", "push", "origin", "HEAD:$ENV{GITHUB_REF}") == 0 or die $!;
}
