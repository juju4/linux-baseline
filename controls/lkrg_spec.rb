# frozen_string_literal: true

sysctl_lkrg = attribute('sysctl_lkrg', default: false, description: 'Checking lkrg module?')

container_execution = begin
                        virtualization.role == 'guest' && virtualization.system =~ /^(lxc|docker)$/
                      rescue NoMethodError
                        false
                      end
syslog_file = if os.redhat?
                '/var/log/messages'
              else
                '/var/log/syslog'
              end

control 'lkrg-01' do
  impact 1.0
  title 'Check lkrg files'
  only_if { sysctl_lkrg }
  describe file('/etc/systemd/system/lkrg.service') do
    it { should exist }
    it { should be_file }
    it { should be_owned_by 'root' }
    it { should_not be_executable }
    it { should_not be_readable.by('other') }
  end
end

control 'lkrg-02' do
  impact 1.0
  title 'Lkrg sysctl'
  desc 'Verifying lkrg sysctl entries'
  only_if { sysctl_lkrg && !container_execution }
  describe kernel_parameter('lkrg.block_modules') do
    its(:value) { should eq 0 }
  end
  describe kernel_parameter('lkrg.ci_panic') do
    its(:value) { should eq 0 }
  end
end

control 'lkrg-03' do
  impact 1.0
  title 'Lkrg module'
  desc 'Verifying lkrg module'
  only_if { sysctl_lkrg && !container_execution }
  describe command('find /lib/modules/ -iname p_lkrg.ko') do
    its('stdout') { should match(/p_lkrg.ko/) }
  end
  describe command('modinfo p_lkrg') do
    its('stdout') { should match(/pi3's Linux kernel Runtime Guard/) }
    its('stdout') { should match %r{Adam 'pi3' Zabrocki \(http://pi3.com.pl\)} }
  end
end

control 'lkrg-4.0' do
  impact 1.0
  title 'Lkrg should have log entries (syslog)'
  desc 'Ensure syslog logs have expected entries for lkrg'
  only_if { sysctl_lkrg && !container_execution }
  describe file(syslog_file.to_s) do
    it { should be_file }
    its('content') { should match '[p_lkrg] Loading LKRG...' }
    its('content') { should match '[p_lkrg] LKRG initialized successfully!' }
    its('content') { should_not match 'COMPROMISED' }
  end
end
