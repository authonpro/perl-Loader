#!/usr/bin/perl
use strict;
use warnings;
use lib '.';
use Authon;

my $auth = Authon->new('your-app-id', 'your-api-key');

unless ($auth->init()) { die "[-] Connection failed\n"; }
print "[+] Connected: $auth->{app_name} v$auth->{app_version}\n";

print "\n[1] Login\n[2] License Key\n> ";
chomp(my $choice = <STDIN>);

my $result;
if ($choice eq '1') {
    print "Username: "; chomp(my $u = <STDIN>);
    print "Password: "; chomp(my $p = <STDIN>);
    $result = $auth->login($u, $p);
} else {
    print "License Key: "; chomp(my $k = <STDIN>);
    $result = $auth->license($k);
}

unless ($result->{success}) { die "\n[-] $result->{message}\n"; }

print "\n[+] Authenticated! Level: $auth->{level}\n";
my $msg = $auth->get_var('welcome_message');
print "[*] $msg\n" if $msg;
$auth->log_msg('Perl SDK example executed');
print "[+] Done.\n";
$auth->logout();
