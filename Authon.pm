package Authon;

# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  Authon Perl SDK — Software Licensing & Authentication                     ║
# ║  Version: 1.0.0                                                            ║
# ║  Dependencies: LWP::UserAgent, JSON, Digest::MD5                           ║
# ║                                                                            ║
# ║  Website: https://authon.pro                                               ║
# ║  Docs:    https://authon.pro/docs                                          ║
# ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
# ║  Status:  https://authon.pro/status                                        ║
# ║  Health:  https://api.authon.pro/health                                    ║
# ║  GitHub:  https://github.com/authonpro                                     ║
# ║                                                                            ║
# ║  Usage:                                                                    ║
# ║    use Authon;                                                             ║
# ║    my $auth = Authon->new(app_id => 'id', api_key => 'key');               ║
# ║    $auth->init();                                                          ║
# ║    my $result = $auth->login('user', 'pass');                              ║
# ║    print "Welcome $auth->{username}\n" if $result->{success};              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

use strict;
use warnings;
use LWP::UserAgent;
use HTTP::Request;
use JSON qw(encode_json decode_json);
use Digest::MD5 qw(md5_hex);
use Sys::Hostname;

our $VERSION = '1.0.0';

use constant DEFAULT_API_URL => 'https://api.authon.pro/v1';
use constant DEFAULT_TIMEOUT => 15;

=head1 NAME

Authon - Perl SDK for Authon Software Licensing & Authentication

=head1 SYNOPSIS

    use Authon;

    my $auth = Authon->new(
        app_id  => 'your-app-id',
        api_key => 'your-api-key',
    );

    $auth->init() or die "Init failed: $auth->{last_error}";

    my $result = $auth->login('username', 'password');
    if ($result->{success}) {
        print "Welcome $auth->{username}! Level: $auth->{level}\n";
    }

=head1 DESCRIPTION

Official Perl SDK for the Authon authentication and licensing platform.
Provides methods for initialization, authentication, session management,
variable storage, file downloads, and activity logging.

=cut

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTRUCTOR
# ═══════════════════════════════════════════════════════════════════════════════

=head2 new(%options)

Creates a new Authon client.

    my $auth = Authon->new(
        app_id  => 'your-app-id',  # Required
        api_key => 'your-api-key', # Required
        api_url => 'https://api.authon.pro/v1',  # Optional
        timeout => 15,             # Optional (seconds)
    );

=cut

sub new {
    my ($class, %opts) = @_;

    die "app_id is required" unless $opts{app_id};
    die "api_key is required" unless $opts{api_key};

    my $self = bless {
        # Config
        app_id  => $opts{app_id},
        api_key => $opts{api_key},
        api_url => $opts{api_url} || DEFAULT_API_URL,
        timeout => $opts{timeout} || DEFAULT_TIMEOUT,

        # Session state
        session_token => undef,
        username      => undef,
        level         => 0,
        subscription  => undef,
        expires_at    => undef,

        # App info
        app_name    => undef,
        app_version => undef,
        hwid_lock   => 0,
        hash_check  => 0,
        initialized => 0,

        # Internal
        last_error => undef,
        _ua        => undef,
    }, $class;

    # Create user agent
    $self->{_ua} = LWP::UserAgent->new(
        timeout => $self->{timeout},
        agent   => "Authon-Perl-SDK/$VERSION",
    );

    return $self;
}

=head2 is_authenticated()

Returns true if the client has an active session.

=cut

sub is_authenticated {
    my ($self) = @_;
    return defined($self->{session_token}) && length($self->{session_token}) > 0;
}

# ═══════════════════════════════════════════════════════════════════════════════
# HWID GENERATION
# ═══════════════════════════════════════════════════════════════════════════════

=head2 get_hwid()

Generates a hardware ID unique to the current machine.
Windows: disk serial + hostname. Linux: /etc/machine-id. Mac: hostname.

Returns a 32-character lowercase hex MD5 hash.

=cut

sub get_hwid {
    my $raw = '';

    if ($^O eq 'MSWin32' || $^O eq 'cygwin') {
        # Windows: wmic disk serial
        my $output = `wmic diskdrive get serialnumber 2>NUL`;
        if ($output) {
            my @lines = split /\n/, $output;
            if (scalar @lines > 1) {
                $raw = $lines[1];
                $raw =~ s/^\s+|\s+$//g;
            }
        }
        $raw .= hostname();
    } elsif ($^O eq 'darwin') {
        # macOS
        my $output = `system_profiler SPHardwareDataType 2>/dev/null`;
        if ($output) {
            for my $line (split /\n/, $output) {
                if ($line =~ /UUID/) {
                    my @parts = split /:/, $line, 2;
                    if (scalar @parts >= 2) {
                        $raw = $parts[1];
                        $raw =~ s/^\s+|\s+$//g;
                        last;
                    }
                }
            }
        }
        $raw = hostname() . $^O unless $raw;
    } else {
        # Linux
        if (-f '/etc/machine-id') {
            open my $fh, '<', '/etc/machine-id';
            $raw = <$fh>;
            chomp $raw;
            close $fh;
        } else {
            $raw = hostname() . $^O;
        }
    }

    $raw = 'fallback-' . hostname() unless $raw;
    return md5_hex($raw);
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL HTTP
# ═══════════════════════════════════════════════════════════════════════════════

sub _request {
    my ($self, $payload) = @_;

    $payload->{appId}  = $self->{app_id};
    $payload->{apiKey} = $self->{api_key};

    my $json = encode_json($payload);

    my $req = HTTP::Request->new('POST', $self->{api_url});
    $req->header('Content-Type' => 'application/json');
    $req->content($json);

    my $resp = $self->{_ua}->request($req);

    unless ($resp->is_success || $resp->content) {
        $self->{last_error} = "Connection failed. Check https://authon.pro/status";
        return { success => 0, message => $self->{last_error} };
    }

    my $content_type = $resp->header('Content-Type') || '';
    if ($content_type =~ /octet-stream/) {
        return { success => 1, binary => $resp->content };
    }

    my $result;
    eval {
        $result = decode_json($resp->content);
    };
    if ($@) {
        $self->{last_error} = "Invalid response from server";
        return { success => 0, message => $self->{last_error} };
    }

    return $result;
}

# ═══════════════════════════════════════════════════════════════════════════════
# INITIALIZATION
# ═══════════════════════════════════════════════════════════════════════════════

=head2 init()

Initializes the connection to the Authon API.
Must be called before any other API method.

Returns the response hashref. On success, sets app_name, app_version, etc.

=cut

sub init {
    my ($self) = @_;

    my $result = $self->_request({ type => 'init' });

    if ($result->{success}) {
        my $data = $result->{data} || {};
        $self->{app_name}    = $data->{name};
        $self->{app_version} = $data->{version};
        $self->{hwid_lock}   = $data->{hwidLock} || 0;
        $self->{hash_check}  = $data->{hashCheck} || 0;
        $self->{initialized} = 1;
    } else {
        $self->{last_error} = $result->{message};
    }

    return $result;
}

# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION
# ═══════════════════════════════════════════════════════════════════════════════

=head2 login($username, $password, $hwid)

Authenticates with username and password.
$hwid is optional (auto-generated if not provided).

Returns hashref: { success => 1/0, message => '...', data => {...} }

Possible errors: "Invalid credentials", "Account banned",
"Hardware ID mismatch", "Subscription expired", "Account is frozen"

=cut

sub login {
    my ($self, $username, $password, $hwid) = @_;

    unless ($username && $password) {
        return { success => 0, message => 'Username and password are required' };
    }

    $hwid //= get_hwid();

    my $result = $self->_request({
        type     => 'login',
        username => $username,
        password => $password,
        hwid     => $hwid,
    });

    if ($result->{success}) {
        $self->_extract_session($result->{data});
    } else {
        $self->{last_error} = $result->{message};
    }

    return $result;
}

=head2 license($license_key, $hwid)

Authenticates using a license key only.

=cut

sub license {
    my ($self, $license_key, $hwid) = @_;

    unless ($license_key) {
        return { success => 0, message => 'License key is required' };
    }

    $hwid //= get_hwid();

    my $result = $self->_request({
        type       => 'license',
        licenseKey => $license_key,
        hwid       => $hwid,
    });

    if ($result->{success}) {
        $self->_extract_session($result->{data});
    } else {
        $self->{last_error} = $result->{message};
    }

    return $result;
}

=head2 register($username, $password, $license_key, $hwid)

Registers a new user account with a license key.

=cut

sub register {
    my ($self, $username, $password, $license_key, $hwid) = @_;

    unless ($username && $password && $license_key) {
        return { success => 0, message => 'Username, password, and license_key are required' };
    }

    $hwid //= get_hwid();

    return $self->_request({
        type       => 'register',
        username   => $username,
        password   => $password,
        licenseKey => $license_key,
        hwid       => $hwid,
    });
}

# ═══════════════════════════════════════════════════════════════════════════════
# SESSION MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

=head2 check()

Validates the current session (heartbeat). Returns 1 if valid, 0 otherwise.

=cut

sub check {
    my ($self) = @_;
    return 0 unless $self->is_authenticated();

    my $result = $self->_request({
        type         => 'check',
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? 1 : 0;
}

=head2 logout()

Ends the current session and clears local state.

=cut

sub logout {
    my ($self) = @_;
    return 0 unless $self->is_authenticated();

    my $result = $self->_request({
        type         => 'logout',
        sessionToken => $self->{session_token},
    });

    if ($result->{success}) {
        $self->{session_token} = undef;
        $self->{username}      = undef;
        $self->{level}         = 0;
        $self->{subscription}  = undef;
        $self->{expires_at}    = undef;
    }

    return $result->{success} ? 1 : 0;
}

# ═══════════════════════════════════════════════════════════════════════════════
# VARIABLES
# ═══════════════════════════════════════════════════════════════════════════════

=head2 get_var($key)

Gets an application-level variable. Returns the value or undef.

=cut

sub get_var {
    my ($self, $key) = @_;

    my $result = $self->_request({
        type         => 'var',
        key          => $key,
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? $result->{data}{value} : undef;
}

=head2 set_var($key, $value)

Sets a user-level variable. Returns 1 on success, 0 on failure.

=cut

sub set_var {
    my ($self, $key, $value) = @_;

    my $result = $self->_request({
        type         => 'setvar',
        key          => $key,
        value        => $value // '',
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? 1 : 0;
}

=head2 get_user_var($key)

Gets a user-level variable. Returns the value or undef.

=cut

sub get_user_var {
    my ($self, $key) = @_;

    my $result = $self->_request({
        type         => 'getvar',
        key          => $key,
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? $result->{data}{value} : undef;
}

# ═══════════════════════════════════════════════════════════════════════════════
# FILES
# ═══════════════════════════════════════════════════════════════════════════════

=head2 list_files()

Lists all files available to the authenticated user.
Returns an arrayref of file hashrefs [{id, name, size, minLevel}].

=cut

sub list_files {
    my ($self) = @_;

    my $result = $self->_request({
        type         => 'list_files',
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? ($result->{data} || []) : [];
}

=head2 download_file($file_id)

Downloads a file by ID. Returns raw binary content or undef.

=cut

sub download_file {
    my ($self, $file_id) = @_;
    return undef unless $self->is_authenticated() && $file_id;

    my $result = $self->_request({
        type         => 'file',
        fileId       => $file_id,
        sessionToken => $self->{session_token},
    });

    return $result->{binary} if $result->{binary};

    # GET fallback
    my $url = "$self->{api_url}/files/download/$file_id?token=$self->{session_token}";
    my $resp = $self->{_ua}->get($url);
    my $ct = $resp->header('Content-Type') || '';
    if ($ct =~ /octet-stream/) {
        return $resp->content;
    }

    return undef;
}

# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING & ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════

=head2 log($message)

Sends an activity log message to the dashboard. Returns 1/0.

=cut

sub log {
    my ($self, $message) = @_;
    $message = substr($message, 0, 500) if length($message) > 500;

    my $result = $self->_request({
        type         => 'log',
        message      => $message,
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? 1 : 0;
}

=head2 fetch_online()

Gets the list of currently online users. Returns { count => N, users => [...] }.

=cut

sub fetch_online {
    my ($self) = @_;

    my $result = $self->_request({
        type         => 'fetch_online',
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? $result->{data} : { count => 0, users => [] };
}

=head2 fetch_stats()

Gets application statistics. Returns { totalUsers, onlineUsers, totalKeys, appVersion }.

=cut

sub fetch_stats {
    my ($self) = @_;

    my $result = $self->_request({
        type         => 'fetch_stats',
        sessionToken => $self->{session_token},
    });

    return $result->{success} ? $result->{data} : {};
}

# ═══════════════════════════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════════════════════════

=head2 check_blacklist(%opts)

Checks if an IP or HWID is blacklisted.

    my $result = $auth->check_blacklist(ip => '1.2.3.4', hwid => 'abc123');
    print "Blacklisted!" if $result->{blacklisted};

=cut

sub check_blacklist {
    my ($self, %opts) = @_;

    my $payload = { type => 'check_blacklist' };
    $payload->{ip}   = $opts{ip}   if $opts{ip};
    $payload->{hwid} = $opts{hwid} if $opts{hwid};

    my $result = $self->_request($payload);
    return $result->{success} ? $result->{data} : { blacklisted => 0, reason => undef };
}

=head2 redeem_referral($code)

Redeems a referral code for bonus subscription days.

=cut

sub redeem_referral {
    my ($self, $code) = @_;

    return $self->_request({
        type         => 'redeem_referral',
        code         => $code,
        sessionToken => $self->{session_token},
    });
}

# ═══════════════════════════════════════════════════════════════════════════════
# INTERNAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

sub _extract_session {
    my ($self, $data) = @_;
    return unless ref $data eq 'HASH';

    $self->{session_token} = $data->{sessionToken};
    $self->{username}      = $data->{username};
    $self->{level}         = $data->{level} || 0;
    $self->{subscription}  = $data->{subscription};
    $self->{expires_at}    = $data->{expiresAt};
}

1;

__END__

=head1 AUTHOR

Authon Team - L<https://authon.pro>

=head1 LICENSE

MIT License

=cut
