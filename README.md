# Authon Perl SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official Perl SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/MTY79JDFm6">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- Perl 5.20+
- Modules: LWP::UserAgent, JSON (usually pre-installed)

## Quick Start

```perl
use Authon;

my $auth = Authon->new('your-app-id', 'your-api-key');
$auth->init();

my $result = $auth->login('username', 'password');
if ($result->{success}) {
    print "Level: $auth->{level}\n";
}
$auth->logout();
```

## Run Example

```bash
perl example.pl
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/MTY79JDFm6
- 📊 Status: https://authon.pro/status

## License

MIT
