#
# Copyright 2018, juju4
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: juju4

iptables_check = attribute('iptables_check', default: true, description: 'Control usage of iptables')
iptables_default_rule = attribute('iptables_default_rule', default: 'DROP', description: 'Default policy action for iptables')
iptables_openports = attribute(
    'iptables_openports', 
    default: %w(
      -A INPUT -p tcp --dport 22 -j ACCEPT
    ),
    description: 'list of iptable rules to check for open ports'
  )

control 'iptables-01' do
  impact 1.0
  title 'IPtables installed'
  desc "CIS 3.6.1 - Ensure iptables is installed"
  describe file('/sbin/iptables') do
    it { should exist }
  end
  only_if { iptables_check == true }
end

control 'iptables-02' do
  impact 1.0
  title 'IPtables default deny policy'
  desc 'CIS 3.6.2 - Ensure default deny firewall policy'
  describe iptables do
    it { should have_rule("-P INPUT #{iptables_default_rule}") }
    it { should have_rule("-P OUTPUT #{iptables_default_rule}") }
    it { should have_rule("-P FORWARD #{iptables_default_rule}") }
  end
  only_if { iptables_check == true }
end

control 'iptables-03' do
  impact 1.0
  title 'IPtables loopback allow policy'
  desc 'CIS 3.6.3 - Ensure loopback traffic is configured'
  describe iptables do
    it { should have_rule("-A INPUT -i lo -j ACCEPT") }
    it { should have_rule("-A OUTPUT -o lo -j ACCEPT") }
    # No option to ensure right order...
    it { should have_rule("-A INPUT -s 127.0.0.0/8 -j DROP") }
  end
  only_if { iptables_check == true }
end

control 'iptables-04' do
  impact 1.0
  title 'IPtables outbound and established allow policy'
  desc 'CIS 3.6.4 - Ensure outbound and established connections are configured'
  describe iptables do
    it { should have_rule("-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT") }
    it { should have_rule("-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT") }
    it { should have_rule("-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT") }
    it { should have_rule("-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT") }
    it { should have_rule("-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT") }
    it { should have_rule("-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT") }
  end
  only_if { iptables_check == true }
end

control 'iptables-05' do
  impact 1.0
  title 'IPtables open ports'
  desc 'CIS 3.6.5 - Ensure firewall rules exists for all open ports'
  describe iptables do
    iptables_openports.each do |port_rule|
      it { should have_rule("#{port_rule}") }
    end
  end
  only_if { iptables_check == true }
end
