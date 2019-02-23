# frozen_string_literal: true

swap_check = attribute('swap_check', default: true, description: 'Control swap settings')
encryptedswap_check = attribute('encryptedswap_check', default: true, description: 'Control /etc/crypttab settings')

control 'swap-01' do
  impact 1.0
  title 'Swap settings'
  describe file('/proc/sys/vm/swappiness').content.to_i do
    it { should <= 60 }
  end
  only_if { swap_check == true }
end

control 'swap-02' do
  impact 1.0
  title 'Swap Encrypted?'
  describe file('/etc/crypttab') do
    it { should exist }
    its(:content) { should match(/ swap/) }
  end
  only_if { encryptedswap_check == true }
end
