# frozen_string_literal: true

profile_check = attribute('profile_check', default: true, description: 'Control /etc/profile settings')
profile_file = attribute('profile_file', default: '/etc/profile', description: 'Control which file to check for settings')
profile_tmout = attribute('profile_tmout', default: 3600, description: 'Value for shell Timeout')
profile_histfilesize = attribute('profile_histfilesize', default: 5000, description: 'Value for HISTFILESIZE')
profile_histsize = attribute('profile_histsize', default: 5000, description: 'Value for HISTSIZE')

control 'profile-01' do
  impact 1.0
  title 'Shell profile settings'
  describe file(profile_file) do
    it { should exist }
    its(:content) { should match "readonly TMOUT=#{profile_tmout}" }
    its(:content) { should match(/export HISTCONTROL=$/) }
    its(:content) { should match 'export HISTFILE=\$HOME/.bash_history' }
    its(:content) { should match "export HISTFILESIZE=#{profile_histfilesize}" }
    its(:content) { should match(/export HISTIGNORE=$/) }
    its(:content) { should match "export HISTSIZE=#{profile_histsize}" }
    its(:content) { should match 'export HISTTIMEFORMAT="%a %b %Y %T %z"' }
  end
  only_if { profile_check == true }
end
