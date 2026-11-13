#!/usr/local/bin/perl

# mkdir-p.pl

# On some systems, the -p option to mkdir (= also create any missing parent
# directories) is not available.

my $quiet = 0;
my $arg;

while (@ARGV) {
  if ($ARGV[0] eq '-q' || $ARGV[0] eq '--quiet') {
    $quiet = 1;
    shift @ARGV;
  } elsif ($ARGV[0] eq '--help') {
    print "Usage: mkdir-p.pl [-q|--quiet] [--] directory ...\n";
    exit 0;
  } elsif ($ARGV[0] eq '--') {
    shift @ARGV;
    last;
  } else {
    last;
  }
}

foreach $arg (@ARGV) {
  $arg =~ tr|\\|/|;
  &do_mkdir_p($arg);
}


sub do_mkdir_p {
  local($dir) = @_;

  $dir =~ s|/*\Z(?!\n)||s;

  if (-d $dir) {
    return;
  }

  if ($dir =~ m|[^/]/|s) {
    local($parent) = $dir;
    $parent =~ s|[^/]*\Z(?!\n)||s;

    do_mkdir_p($parent);
  }

  mkdir($dir, 0777) || die "Cannot create directory $dir: $!\n";
  print "created directory `$dir'\n" unless $quiet;
}
