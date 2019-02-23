# frozen_string_literal: true

cpu_check = attribute('cpu_check', default: false, description: 'Control CPU state against hardware vulnerabilities - kernel 4.15+')

control 'cpu-01' do
  impact 1.0
  title 'Trusted hosts login'
  only_if { cpu_check }
  reference 'https://www.linux.com/blog/intro-to-linux/2018/1/linux-kernel-415-unusual-release-cycle'
  describe file('/sys/devices/system/cpu/vulnerabilities/meltdown') do
    it { should exist }
    its(:content) { should match 'Mitigation: PTI' }
  end
  describe file('/sys/devices/system/cpu/vulnerabilities/spec_store_bypass') do
    it { should exist }
    its(:content) { should_not match 'Vulnerable' }
  end
end
