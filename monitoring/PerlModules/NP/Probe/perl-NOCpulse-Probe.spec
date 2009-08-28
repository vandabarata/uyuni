Name:         perl-NOCpulse-Probe
Summary:      Probe execution framework
URL:          https://fedorahosted.org/spacewalk
Source0:      https://fedorahosted.org/releases/s/p/spacewalk/%{name}-%{version}.tar.gz
Version:      1.183.9
Release:      1%{?dist}
BuildArch:    noarch
Group:        Development/Libraries
Requires:     perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
License:      GPLv2
Buildroot:    %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Requires(pre): nocpulse-common

%description
NOCpulse provides application, network, systems and transaction monitoring,
coupled with a comprehensive reporting system including availability,
historical and trending reports in an easy-to-use browser interface.

This package provides classes for executing probes.

%prep
%setup -q

%build
#Nothing to build

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Config/test
mkdir -p $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/DataSource/test
mkdir -p $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/test
mkdir -p $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Utils/test
mkdir -p $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/SNMP/test
mkdir -p $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/test

install -m 755 -D rhn-runprobe $RPM_BUILD_ROOT%{_bindir}/rhn-runprobe
install -m 755 monitoring-data-cleanup $RPM_BUILD_ROOT%{_bindir}/monitoring-data-cleanup 
install -m 644 Config/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Config/
install -m 644 Config/test/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Config/test/
install -m 644 DataSource/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/DataSource/
install -m 644 DataSource/test/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/DataSource/test/
install -m 644 SNMP/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/SNMP/
install -m 644 SNMP/test/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/SNMP/test/
install -m 644 Shell/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/
install -m 644 Shell/test/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/test/
install -m 644 Utils/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Utils/
install -m 644 Utils/test/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Utils/test/
install -m 644 *.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/
install -m 644 test/*.pm $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/test/

mkdir -p $RPM_BUILD_ROOT%{_mandir}/man3
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/ItemStatus.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::ItemStatus.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/DataSource/MySQL.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::DataSource::MySQL.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/DataSource/NetworkServiceCommand.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::DataSource::NetworkServiceCommand.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Result.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::Result.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/AbstractShell.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::Shell::AbstractShell.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/SSH.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::Shell::SSH.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/SQLPlus.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::Shell::SQLPlus.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/Local.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::Shell::Local.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT%{perl_vendorlib}/NOCpulse/Probe/Shell/Unix.pm |gzip > $RPM_BUILD_ROOT%{_mandir}/man3/NOCpulse::Probe::Shell::Unix.3pm.gz
/usr/bin/pod2man $RPM_BUILD_ROOT/%{_bindir}/monitoring-data-cleanup | gzip > $RPM_BUILD_ROOT%{_mandir}/man3/monitoring-data-cleanup.3pm.gz

%clean
rm -rf $RPM_BUILD_ROOT

%files 
%defattr(-,root,root,-)
%{_bindir}/rhn-runprobe
%{_bindir}/monitoring-data-cleanup
%dir %{perl_vendorlib}/NOCpulse
%{perl_vendorlib}/NOCpulse/*
%{_mandir}/man3/*
%doc LICENSE

%changelog
* Thu Jul 23 2009 Miroslav Suchý <msuchy@redhat.com> 1.183.9-1
- 512749 -  fix path to file during man page generation

* Wed Apr 15 2009 Devan Goodwin <dgoodwin@redhat.com> 1.183.7-1
- fix various perl -w warnings (msuchy@redhat.com)
- Fix ownership of nocpulse directory (msuchy@redhat.com)
- Add LICENSE file (msuchy@redhat.com)
- Remove unused macro definition (msuchy@redhat.com)

* Tue Jan 13 2009 Milan Zazrivec 1.183.6-1
- point ssh to correct private key

* Tue Jan 13 2009 Miroslav Suchý <msuchy@redhat.com> 1.183.5-1
- 479441 - this one should not be part of namespace fix

* Tue Dec 16 2008 Miroslav Suchý <msuchy@redhat.com> 1.183.4-1
- 472895 - remove grouped_fields from Class::MethodMaker declaration

* Mon Oct 20 2008 Miroslav Suchý <msuchy@redhat.com> 1.183.3-1
- 467441 - fix namespace

* Tue Sep  2 2008 Miroslav Suchý <msuchy@redhat.com> 1.183.2-1
- edit spec to comply with Fedora guidelines

* Thu Jun 19 2008 Miroslav Suchy <msuchy@redhat.com>
- migrating nocpulse home dir (BZ 202614)

* Wed Jun  4 2008 Milan Zazrivec <mzazrivec@redhat.com> 1.183.1-22
- fixed file permissions

* Wed May 28 2008 Jan Pazdziora 1.183.1-21
- rebuild in dist-cvs
