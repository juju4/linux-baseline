# frozen_string_literal: true

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
iptables_default_policy = attribute(
  'iptables_default_policy',
  default: [
    "-P INPUT #{iptables_default_rule}",
    "-P OUTPUT #{iptables_default_rule}",
    "-P FORWARD #{iptables_default_rule}"
  ],
  description: 'list of iptable rules to check for default policy'
)
iptables_loopback_policy = attribute(
  'iptables_loopback_policy',
  default: [
    '-A INPUT -i lo -j ACCEPT',
    '-A OUTPUT -o lo -j ACCEPT',
    # No option to ensure right order...
    '-A INPUT -s 127.0.0.0/8 -j DROP'
  ],
  description: 'list of iptable rules to check for loopback policy'
)
iptables_established_policy = attribute(
  'iptables_established_policy',
  default: [
    '-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT',
    '-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT',
    '-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT',
    '-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT',
    '-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT',
    '-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT'
  ],
  description: 'list of iptable rules to check for established allow policy'
)
iptables_input_ports = attribute(
  'iptables_input_ports',
  default: [
    '-A INPUT -p tcp --dport 22 -j ACCEPT',
    '-A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT',
    '-A INPUT -p icmp --icmp-type 0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
  ],
  description: 'list of iptable rules to check for input rules'
)
iptables_output_ports = attribute(
  'iptables_output_ports',
  default: [
    '-A OUTPUT -p tcp --dport 53 -j ACCEPT',
    '-A OUTPUT -p udp --dport 53 -j ACCEPT',
    '-A OUTPUT -p udp --dport 123 -j ACCEPT',
    '-A OUTPUT -p tcp --dport 80 -j ACCEPT',
    '-A OUTPUT -p tcp --dport 443 -j ACCEPT',
    '-A OUTPUT -p icmp --icmp-type 0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT',
    '-A OUTPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT',
    '-A OUTPUT -p icmp --icmp-type 3 -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT'
  ],
  description: 'list of iptable rules to check for output rules'
)
iptables_forward_ports = attribute(
  'iptables_forward_ports',
  default: [],
  description: 'list of iptable rules to check for forward rules'
)

control 'iptables-01' do
  impact 1.0
  title 'IPtables installed'
  desc 'CIS 3.6.1 - Ensure iptables is installed'
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
    iptables_default_policy.each do |port_rule|
      it { should have_rule(port_rule.to_s) }
    end
  end
  only_if { iptables_check == true }
end

control 'iptables-03' do
  impact 1.0
  title 'IPtables loopback allow policy'
  desc 'CIS 3.6.3 - Ensure loopback traffic is configured'
  describe iptables do
    iptables_loopback_policy.each do |port_rule|
      it { should have_rule(port_rule.to_s) }
    end
  end
  only_if { iptables_check == true }
end

control 'iptables-04' do
  impact 1.0
  title 'IPtables outbound and established allow policy'
  desc 'CIS 3.6.4 - Ensure outbound and established connections are configured'
  describe iptables do
    iptables_established_policy.each do |port_rule|
      it { should have_rule(port_rule.to_s) }
    end
  end
  only_if { iptables_check == true }
end

control 'iptables-05' do
  impact 1.0
  title 'IPtables open ports'
  desc 'CIS 3.6.5 - Ensure firewall rules exists for all open ports'
  describe iptables do
    iptables_input_ports.each do |port_rule|
      it { should have_rule(port_rule.to_s) }
    end
    iptables_output_ports.each do |port_rule|
      it { should have_rule(port_rule.to_s) }
    end
    iptables_forward_ports.each do |port_rule|
      it { should have_rule(port_rule.to_s) }
    end
  end
  only_if { iptables_check == true }
end
