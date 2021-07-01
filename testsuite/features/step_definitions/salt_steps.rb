# Copyright 2015-2022 SUSE LLC
# Licensed under the terms of the MIT license.

require 'timeout'
require 'open-uri'
require 'tempfile'

Given(/^the Salt master can reach "(.*?)"$/) do |minion|
  system_name = get_system_name(minion)
  start = Time.now
  # 300 is the default 1st keepalive interval for the minion
  # where it realizes the connection is stuck
  repeat_until_timeout(timeout: 300, retries: 3, message: "Master can not communicate with #{minion}", report_result: true) do
    out, _code = $server.run("salt #{system_name} test.ping")
    if out.include?(system_name) && out.include?('True')
      finished = Time.now
      log "Took #{finished.to_i - start.to_i} seconds to contact the minion"
      break
    end
    sleep 1
    out
  end
end

When(/^I get the contents of the remote file "(.*?)"$/) do |filename|
  $output, _code = $server.run("cat #{filename}")
end

When(/^I stop salt-minion on "(.*?)"$/) do |minion|
  node = get_target(minion)
  ## Uyuni uses Salt Bundle. Package name is "venv-salt-minion"
  pkgname = $product == 'Uyuni' ? "venv-salt-minion" : "salt-minion"
  node.run("rc#{pkgname} stop", check_errors: false) if minion == 'sle_minion'
  node.run("systemctl stop #{pkgname}", check_errors: false) if %w[ceos_minion ubuntu_minion kvm_server xen_server].include?(minion)
end

When(/^I start salt-minion on "(.*?)"$/) do |minion|
  node = get_target(minion)
  ## Uyuni uses Salt Bundle. Package name is "venv-salt-minion"
  pkgname = $product == 'Uyuni' ? "venv-salt-minion" : "salt-minion"
  node.run("rc#{pkgname} restart", check_errors: false) if minion == 'sle_minion'
  node.run("systemctl restart #{pkgname}", check_errors: false) if %w[ceos_minion ubuntu_minion kvm_server xen_server].include?(minion)
end

When(/^I restart salt-minion on "(.*?)"$/) do |minion|
  node = get_target(minion)
  ## Uyuni uses Salt Bundle. Package name is "venv-salt-minion"
  pkgname = $product == 'Uyuni' ? "venv-salt-minion" : "salt-minion"
  node.run("rc#{pkgname} restart", check_errors: false) if minion == 'sle_minion'
  node.run("systemctl restart #{pkgname}", check_errors: false) if %w[ceos_minion ubuntu_minion kvm_server xen_server].include?(minion)
end

When(/^I refresh salt-minion grains on "(.*?)"$/) do |minion|
  node = get_target(minion)
  salt_call = $product == 'Uyuni' ? "venv-salt-call" : "salt-call"
  node.run("#{salt_call} saltutil.refresh_grains")
end

When(/^I wait at most (\d+) seconds until Salt master sees "([^"]*)" as "([^"]*)"$/) do |key_timeout, minion, key_type|
  cmd = "salt-key --list #{key_type}"
  repeat_until_timeout(timeout: key_timeout.to_i, message: "Minion '#{minion}' is not listed among #{key_type} keys on Salt master") do
    system_name = get_system_name(minion)
    unless system_name.empty?
      output, return_code = $server.run(cmd, check_errors: false)
      break if return_code.zero? && output.include?(system_name)
    end
    sleep 1
  end
end

When(/^I wait until no Salt job is running on "([^"]*)"$/) do |minion|
  target = get_target(minion)
  salt_call = $product == 'Uyuni' ? "venv-salt-call" : "salt-call"
  repeat_until_timeout(message: "A Salt job is still running on #{minion}") do
    output, _code = target.run("#{salt_call} -lquiet saltutil.running")
    break if output == "local:\n"
    sleep 3
  end
end

When(/^I delete "([^"]*)" key in the Salt master$/) do |host|
  system_name = get_system_name(host)
  $output, _code = $server.run("salt-key -y -d #{system_name}", check_errors: false)
end

When(/^I accept "([^"]*)" key in the Salt master$/) do |host|
  system_name = get_system_name(host)
  $server.run("salt-key -y --accept=#{system_name}*")
end

When(/^I reject "([^"]*)" key in the Salt master$/) do |host|
  system_name = get_system_name(host)
  $server.run("salt-key -y --reject=#{system_name}")
end

When(/^I delete all keys in the Salt master$/) do
  $server.run('salt-key -y -D')
end

When(/^I get OS information of "([^"]*)" from the Master$/) do |host|
  system_name = get_system_name(host)
  $output, _code = $server.run("salt #{system_name} grains.get osfullname")
end

Then(/^it should contain a "([^"]*?)" text$/) do |content|
  assert_match(/#{content}/, $output)
end

Then(/^it should contain the OS of "([^"]*)"$/) do |host|
  node = get_target(host)
  _os_version, os_family = get_os_version(node)
  family = os_family =~ /^opensuse/ ? 'Leap' : 'SLES'
  assert_match(/#{family}/, $output)
end

When(/^I apply state "([^"]*)" to "([^"]*)"$/) do |state, host|
  system_name = get_system_name(host)
  $server.run("salt #{system_name} state.apply #{state}")
end

Then(/^salt\-api should be listening on local port (\d+)$/) do |port|
  $output, _code = $server.run("ss -ntl | grep #{port}")
  assert_match(/127.0.0.1:#{port}/, $output)
end

Then(/^salt\-master should be listening on public port (\d+)$/) do |port|
  $output, _code = $server.run("ss -ntl | grep #{port}")
  assert_match(/(0.0.0.0|\*|\[::\]):#{port}/, $output)
end

Then(/^the system should have a base channel set$/) do
  step %(I should not see a "This system has no Base Software Channel. You can select a Base Channel from the list below." text)
end

Then(/^"(.*?)" should not be registered$/) do |host|
  system_name = get_system_name(host)
  @system_api = XMLRPCSystemTest.new(ENV['SERVER'])
  @system_api.login('admin', 'admin')
  refute_includes(@system_api.list_systems.map { |s| s['name'] }, system_name)
end

Then(/^"(.*?)" should be registered$/) do |host|
  system_name = get_system_name(host)
  @system_api = XMLRPCSystemTest.new(ENV['SERVER'])
  @system_api.login('admin', 'admin')
  assert_includes(@system_api.list_systems.map { |s| s['name'] }, system_name)
end

Then(/^the PXE boot minion should have been reformatted$/) do
  system_name = get_system_name('pxeboot_minion')
  output, _code = $server.run("salt #{system_name} file.file_exists /intact")
  raise 'Minion is intact' unless output.include? 'False'
end

# user salt steps
Given(/^I am authorized as an example user with no roles$/) do
  @user_api = XMLRPCUserTest.new(ENV['SERVER'])
  @user_api.login('admin', 'admin')
  @username = 'testuser' + (0...8).map { (65 + rand(26)).chr }.join.downcase
  @user_api.create_user(@username, 'linux')
  step %(I am authorized as "#{@username}" with password "linux")
end

Then(/^I can cleanup the no longer needed user$/) do
  @user_api.delete_user(@username)
end

When(/^I click on preview$/) do
  find('button#preview').click
end

When(/^I click on run$/) do
  find('button#run', wait: DEFAULT_TIMEOUT).click
end

Then(/^I should see "([^"]*)" short hostname$/) do |host|
  system_name = get_system_name(host).partition('.').first
  raise "Hostname #{system_name} is not present" unless has_content?(system_name)
end

Then(/^I should not see "([^"]*)" short hostname$/) do |host|
  system_name = get_system_name(host).partition('.').first
  raise "Hostname #{system_name} is present" if has_content?(system_name)
end

Then(/^I should see "([^"]*)" hostname$/) do |host|
  system_name = get_system_name(host)
  raise "Hostname #{system_name} is not present" unless has_content?(system_name)
end

Then(/^I should not see "([^"]*)" hostname$/) do |host|
  system_name = get_system_name(host)
  raise "Hostname #{system_name} is present" if has_content?(system_name)
end

When(/^I expand the results for "([^"]*)"$/) do |host|
  system_name = get_system_name(host)
  find("div[id='#{system_name}']").click
end

When(/^I enter command "([^"]*)"$/) do |cmd|
  fill_in 'command', with: cmd
end

When(/^I enter target "([^"]*)"$/) do |minion|
  fill_in 'target', with: minion
end

Then(/^I should see "([^"]*)" in the command output for "([^"]*)"$/) do |text, host|
  system_name = get_system_name(host)
  within("pre[id='#{system_name}-results']") do
    raise "Text '#{text}' not found in the results of #{system_name}" unless has_content?(text)
  end
end

# Salt formulas
When(/^I manually install the "([^"]*)" formula on the server$/) do |package|
  $server.run("zypper --non-interactive refresh")
  $server.run("zypper --non-interactive install --force #{package}-formula")
end

Then(/^I wait for "([^"]*)" formula to be installed on the server$/) do |package|
  $server.run_until_ok("rpm -q #{package}-formula")
end

When(/^I manually uninstall the "([^"]*)" formula from the server$/) do |package|
  $server.run("zypper --non-interactive remove #{package}-formula")
end

When(/^I synchronize all Salt dynamic modules on "([^"]*)"$/) do |host|
  system_name = get_system_name(host)
  $server.run("salt #{system_name} saltutil.sync_all")
end

When(/^I remove "([^"]*)" from salt cache on "([^"]*)"$/) do |filename, host|
  node = get_target(host)
  salt_cache = $product == 'Uyuni' ? "/var/cache/venv-salt-minion/" : "/var/cache/salt/"
  file_delete(node, "#{salt_cache}#{filename}")
end

When(/^I remove "([^"]*)" from salt minion config directory on "([^"]*)"$/) do |filename, host|
  node = get_target(host)
  salt_config = $product == 'Uyuni' ? "/etc/venv-salt-minion/minion.d/" : "/etc/salt/minion.d/"
  file_delete(node, "#{salt_config}#{filename}")
end

When(/^I store "([^"]*)" into file "([^"]*)" in salt minion config directory on "([^"]*)"$/) do |content, filename, host|
  salt_config = $product == 'Uyuni' ? "/etc/venv-salt-minion/minion.d/" : "/etc/salt/minion.d/"
  step %(I store "#{content}" into file "#{salt_config}#{filename}" on "#{host}")
end

When(/^I ([^ ]*) the "([^"]*)" formula$/) do |action, formula|
  # Complicated code because the checkbox is not a <input type=checkbox> but an <i>
  xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-square-o']" if action == 'check'
  xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-check-square-o']" if action == 'uncheck'
  # DOM refreshes content of chooseFormulas element by accessing it. Then conditions are evaluated properly.
  find('#chooseFormulas')['innerHTML']
  if has_xpath?(xpath_query, wait: DEFAULT_TIMEOUT)
    raise "xpath: #{xpath_query} not found" unless find(:xpath, xpath_query, wait: DEFAULT_TIMEOUT).click
  else
    xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-check-square-o']" if action == 'check'
    xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-square-o']" if action == 'uncheck'
    raise "xpath: #{xpath_query} not found" unless has_xpath?(xpath_query, wait: DEFAULT_TIMEOUT)
  end
end

Then(/^the "([^"]*)" formula should be ([^ ]*)$/) do |formula, state|
  # Complicated code because the checkbox is not a <input type=checkbox> but an <i>
  xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-square-o']" if state == 'checked'
  xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-check-square-o']" if state == 'unchecked'
  # DOM refreshes content of chooseFormulas element by accessing it. Then conditions are evaluated properly.
  find('#chooseFormulas')['innerHTML']
  raise "Checkbox is not #{state}" if has_xpath?(xpath_query)
  xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-check-square-o']" if state == 'checked'
  xpath_query = "//a[@id = '#{formula}']/i[@class = 'fa fa-lg fa-square-o']" if state == 'unchecked'
  assert has_xpath?(xpath_query), 'Checkbox could not be found'
end

When(/^I select "([^"]*)" in (.*) field$/) do |value, box|
  select(value, from: FIELD_IDS[box])
end

# rubocop:disable Metrics/BlockLength
When(/^I enter the local IP address of "([^"]*)" in (.*) field$/) do |host, field|
  fieldids = { 'IP'                       => 'branch_network#ip',
               'domain name server'       => 'dhcpd#domain_name_servers#0',
               'network IP'               => 'dhcpd#subnets#0#$key',
               'dynamic IP range begin'   => 'dhcpd#subnets#0#range#0',
               'dynamic IP range end'     => 'dhcpd#subnets#0#range#1',
               'broadcast address'        => 'dhcpd#subnets#0#broadcast_address',
               'routers'                  => 'dhcpd#subnets#0#routers#0',
               'next server'              => 'dhcpd#subnets#0#next_server',
               'pxeboot next server'      => 'dhcpd#hosts#2#next_server',
               'first reserved IP'        => 'dhcpd#hosts#0#fixed_address',
               'second reserved IP'       => 'dhcpd#hosts#1#fixed_address',
               'third reserved IP'        => 'dhcpd#hosts#2#fixed_address',
               'internal network address' => 'tftpd#listen_ip',
               'vsftpd internal network address' => 'vsftpd_config#listen_address' }
  fill_in fieldids[field], with: net_prefix + ADDRESSES[host]
end

When(/^I enter "([^"]*)" in (.*) field$/) do |value, field|
  fieldids = { 'NIC'                             => 'branch_network#nic',
               'domain name'                     => 'dhcpd#domain_name',
               'listen interfaces'               => 'dhcpd#listen_interfaces#0',
               'network mask'                    => 'dhcpd#subnets#0#netmask',
               'filename'                        => 'dhcpd#subnets#0#filename',
               'pxeboot filename'                => 'dhcpd#hosts#2#filename',
               'first reserved hostname'         => 'dhcpd#hosts#0#$key',
               'second reserved hostname'        => 'dhcpd#hosts#1#$key',
               'third reserved hostname'         => 'dhcpd#hosts#2#$key',
               'virtual network IPv4 address'    => 'default_net#ipv4#gateway',
               'first IPv4 address for DHCP'     => 'default_net#ipv4#dhcp_start',
               'last IPv4 address for DHCP'      => 'default_net#ipv4#dhcp_end',
               'first option'                    => 'bind#config#options#0#0',
               'first value'                     => 'bind#config#options#0#1',
               'second option'                   => 'bind#config#options#1#0',
               'second value'                    => 'bind#config#options#1#1',
               'third option'                    => 'bind#config#options#2#0',
               'third value'                     => 'bind#config#options#2#1',
               'first configured zone name'      => 'bind#configured_zones#0#$key',
               'first available zone name'       => 'bind#available_zones#0#$key',
               'second configured zone name'     => 'bind#configured_zones#1#$key',
               'second available zone name'      => 'bind#available_zones#1#$key',
               'third configured zone name'      => 'bind#configured_zones#2#$key',
               'third available zone name'       => 'bind#available_zones#2#$key',
               'TFTP base directory'             => 'tftpd#root_dir',
               'branch id'                       => 'pxe#branch_id',
               'disk id'                         => 'partitioning#0#$key',
               'disk device'                     => 'partitioning#0#device',
               'first partition id'              => 'partitioning#0#partitions#0#$key',
               'first partition size'            => 'partitioning#0#partitions#0#size_MiB',
               'first mount point'               => 'partitioning#0#partitions#0#mountpoint',
               'first OS image'                  => 'partitioning#0#partitions#0#image',
               'first partition password'        => 'partitioning#0#partitions#0#luks_pass',
               'second partition id'             => 'partitioning#0#partitions#1#$key',
               'second partition size'           => 'partitioning#0#partitions#1#size_MiB',
               'second mount point'              => 'partitioning#0#partitions#1#mountpoint',
               'second OS image'                 => 'partitioning#0#partitions#1#image',
               'second partition password'       => 'partitioning#0#partitions#1#luks_pass',
               'third partition id'              => 'partitioning#0#partitions#2#$key',
               'third partition size'            => 'partitioning#0#partitions#2#size_MiB',
               'third filesystem format'         => 'partitioning#0#partitions#2#format',
               'third mount point'               => 'partitioning#0#partitions#2#mountpoint',
               'third OS image'                  => 'partitioning#0#partitions#2#image',
               'third partition password'        => 'partitioning#0#partitions#2#luks_pass',
               'FTP server directory'            => 'vsftpd_config#anon_root' }
  fill_in fieldids[field], with: value
end
# rubocop:enable Metrics/BlockLength

When(/^I enter "([^"]*)" in (.*) field of (.*) zone$/) do |value, field, zone|
  fieldids = {
    'file name'                       => '#file',
    'SOA name server'                 => '#soa#ns',
    'SOA contact'                     => '#soa#contact',
    'first A name'                    => '#records#A#0#0',
    'first A address'                 => '#records#A#0#1',
    'second A name'                   => '#records#A#1#0',
    'second A address'                => '#records#A#1#1',
    'third A name'                    => '#records#A#2#0',
    'third A address'                 => '#records#A#2#1',
    'fourth A name'                   => '#records#A#3#0',
    'fourth A address'                => '#records#A#3#1',
    'first NS'                        => '#records#NS#@#0',
    'first CNAME alias'               => '#records#CNAME#0#0',
    'first CNAME name'                => '#records#CNAME#0#1',
    'second CNAME alias'              => '#records#CNAME#1#0',
    'second CNAME name'               => '#records#CNAME#1#1',
    'third CNAME alias'               => '#records#CNAME#2#0',
    'third CNAME name'                => '#records#CNAME#2#1',
    'first for zones'                 => '#generate_reverse#for_zones#0',
    'generate reverse network'        => '#generate_reverse#net'
  }
  zone_xpath = "//input[@name='Name' and @value='#{zone}']/ancestor::div[starts-with(@id, 'bind#available_zones#')]"

  find(:xpath, "#{zone_xpath}//input[contains(@id, '#{fieldids[field]}')]").set(value)
end

When(/^I enter the hostname of "([^"]*)" in (.*) field of (.*) zone$/) do |host, field, zone|
  system_name = get_system_name(host)
  step %(I enter "#{system_name}." in #{field} field of #{zone} zone)
end

When(/^I enter the IP address of "([^"]*)" in (.*) field$/) do |host, field|
  node = get_target(host)
  fill_in FIELD_IDS[field], with: node.public_ip
end

When(/^I enter the IP address of "([^"]*)" in (.*) field of (.*) zone$/) do |host, field, zone|
  node = get_target(host)
  step %(I enter "#{node.public_ip}" in #{field} field of #{zone} zone)
end

When(/^I enter the local IP address of "([^"]*)" in (.*) field of (.*) zone$/) do |host, field, zone|
  net_prefix = $private_net.sub(%r{\.0+/24$}, ".")
  step %(I enter "#{net_prefix + ADDRESSES[host]}" in #{field} field of #{zone} zone)
end

When(/^I enter the MAC address of "([^"]*)" in (.*) field$/) do |host, field|
  if host == 'pxeboot_minion'
    mac = $pxeboot_mac
  elsif host.include? 'ubuntu'
    node = get_target(host)
    output, _code = node.run("ip link show dev ens4")
    mac = output.split("\n")[1].split[1]
  else
    node = get_target(host)
    output, _code = node.run("ip link show dev eth1")
    mac = output.split("\n")[1].split[1]
  end

  fill_in FIELD_IDS[field], with: 'ethernet ' + mac
end

When(/^I enter the local zone name in (.*) field$/) do |field|
  reverse_net = get_reverse_net($private_net)
  log "#{$private_net} => #{reverse_net}"
  step %(I enter "#{reverse_net}" in #{field} field)
end

When(/^I enter the local file name in (.*) field of zone with local name$/) do |field|
  reverse_filename = 'master/db.' + get_reverse_net($private_net)
  log "#{$private_net} => #{reverse_filename}"
  step %(I enter "#{reverse_filename}" in #{field} field of zone with local name)
end

When(/^I enter "([^"]*)" in (.*) field of zone with local name$/) do |value, field|
  reverse_net = get_reverse_net($private_net)
  step %(I enter "#{value}" in #{field} field of #{reverse_net} zone)
end

When(/^I enter the local network in (.*) field of zone with local name$/) do |field|
  step %(I enter "#{$private_net}" in #{field} field of zone with local name)
end

When(/^I enter the image name in (.*) field$/) do |field|
  name = compute_image_name
  fill_in FIELD_IDS[field], with: name
end

When(/^I press "Add Item" in (.*) section$/) do |section|
  sectionids = { 'host reservations' => 'dhcpd#hosts#add_item',
                 'config options'    => 'bind#config#options#add_item',
                 'configured zones'  => 'bind#configured_zones#add_item',
                 'available zones'   => 'bind#available_zones#add_item',
                 'partitions'        => 'partitioning#0#partitions#add_item' }
  find(:xpath, "//i[@id='#{sectionids[section]}']").click
end

When(/^I press "Add Item" in (A|NS|CNAME|for zones) section of (.*) zone$/) do |field, zone|
  sectionids = {
    'for zones' => 'for_zones',
    'NS'       => 'NS#@',
    'CNAME'    => 'CNAME',
    'A'        => 'A'
  }
  xpath = "//input[@name='Name' and @value='#{zone}']/ancestor::div[starts-with(@id, 'bind#available_zones#')]//i[contains(@id, '##{sectionids[field]}#add_item')]"
  find(:xpath, xpath).click
end

When(/^I press "Add Item" in (A|NS|CNAME|for zones) section of zone with local name$/) do |field|
  reverse_net = get_reverse_net($private_net)
  step %(I press "Add Item" in #{field} section of #{reverse_net} zone)
end

When(/^I press "Remove Item" in (.*) CNAME of (.*) zone section$/) do |alias_name, zone|
  cname_xpath = "//input[@name='Name' and @value='#{zone}']/ancestor::div[starts-with(@id, 'bind#available_zones#')]//input[@name='Alias' and @value='#{alias_name}']/ancestor::div[@class='form-group']"
  find(:xpath, "#{cname_xpath}/button").click
end

When(/^I press "Remove" in the routers section$/) do
  cname_xpath = "//div[@id='dhcpd#subnets#0#routers#0']/button"
  find(:xpath, cname_xpath).click
end

When(/^I press minus sign in (.*) section$/) do |section|
  section_xpath = '//input[@name="Name" and @value="%s"]/ancestor::div[starts-with(@id, "bind#%s_zones#")]'
  sectionids = { 'tf.local configured zone' => format(section_xpath, "tf.local", "configured"),
                 'tf.local available zone'  => format(section_xpath, "tf.local", "available") }
  find(:xpath, "#{sectionids[section]}/div[1]/i[@class='fa fa-minus']").click
end

Then(/^the timezone on "([^"]*)" should be "([^"]*)"$/) do |minion, timezone|
  node = get_target(minion)
  output, _code = node.run('date +%Z')
  result = output.strip
  result = 'CET' if result == 'CEST'
  raise "The timezone #{timezone} is different to #{result}" unless result == timezone
end

Then(/^the keymap on "([^"]*)" should be "([^"]*)"$/) do |minion, keymap|
  node = get_target(minion)
  output, _code = node.run("grep 'KEYMAP=' /etc/vconsole.conf")
  raise "The keymap #{keymap} is different to the output: #{output.strip}" unless output.strip == "KEYMAP=#{keymap}"
end

Then(/^the language on "([^"]*)" should be "([^"]*)"$/) do |minion, language|
  node = get_target(minion)
  output, _code = node.run("grep 'RC_LANG=' /etc/sysconfig/language")
  unless output.strip == "RC_LANG=\"#{language}\""
    output, _code = node.run("grep 'LANG=' /etc/locale.conf")
    raise "The language #{language} is different to the output: #{output.strip}" unless output.strip == "LANG=#{language}"
  end
end

When(/^I refresh the pillar data$/) do
  $server.run("salt '#{$minion.full_hostname}' saltutil.refresh_pillar wait=True")
end

When(/^I wait until there is no pillar refresh salt job active$/) do
  repeat_until_timeout(message: "pillar refresh job still active") do
    output, = $server.run("salt-run jobs.active")
    break unless output.include?("saltutil.refresh_pillar")
    sleep 1
  end
end

def pillar_get(key, minion)
  system_name = get_system_name(minion)
  if minion == 'sle_minion'
    cmd = 'salt'
    extra_cmd = ''
  elsif %w[ssh_minion ceos_minion ubuntu_minion].include?(minion)
    cmd = 'salt-ssh'
    extra_cmd = '-i --roster-file=/tmp/roster_tests -w -W 2>/dev/null'
    $server.run("printf '#{system_name}:\n  host: #{system_name}\n  user: root\n  passwd: linux\n' > /tmp/roster_tests")
  else
    raise 'Invalid target'
  end
  $server.run("#{cmd} '#{system_name}' pillar.get '#{key}' #{extra_cmd}")
end

Then(/^the pillar data for "([^"]*)" should be "([^"]*)" on "([^"]*)"$/) do |key, value, minion|
  output, _code = pillar_get(key, minion)
  if value == ''
    raise "Output has more than one line: #{output}" unless output.split("\n").length == 1
  else
    raise "Output value wasn't found: #{output}" unless output.split("\n").length > 1
    raise "Output value is different than #{value}: #{output}" unless output.split("\n")[1].strip == value
  end
end

Then(/^the pillar data for "([^"]*)" should contain "([^"]*)" on "([^"]*)"$/) do |key, value, minion|
  output, _code = pillar_get(key, minion)
  raise "Output doesn't contain #{value}: #{output}" unless output.include? value
end

Then(/^the pillar data for "([^"]*)" should not contain "([^"]*)" on "([^"]*)"$/) do |key, value, minion|
  output, _code = pillar_get(key, minion)
  raise "Output contains #{value}: #{output}" if output.include? value
end

Then(/^the pillar data for "([^"]*)" should be empty on "([^"]*)"$/) do |key, minion|
  output, _code = pillar_get(key, minion)
  raise "Output has more than one line: #{output}" unless output.split("\n").length == 1
end

Given(/^I try to download "([^"]*)" from channel "([^"]*)"$/) do |rpm, channel|
  url = "https://#{$server.full_hostname}/rhn/manager/download/#{channel}/getPackage/#{rpm}"
  url = "#{url}?#{@token}" if @token
  @download_path = nil
  @download_error = nil
  Tempfile.open(rpm) do |tmpfile|
    @download_path = tmpfile.path
    begin
      open(url, ssl_verify_mode: OpenSSL::SSL::VERIFY_NONE) do |urlfile|
        tmpfile.write(urlfile.read)
      end
    rescue OpenURI::HTTPError => e
      @download_error = e
    end
  end
end

Then(/^the download should get a (\d+) response$/) do |code|
  refute_nil(@download_error)
  assert_equal(code.to_i, @download_error.io.status[0].to_i)
end

Then(/^the download should get no error$/) do
  assert_nil(@download_error)
end

# Perform actions
When(/^I reject "([^"]*)" from the Pending section$/) do |host|
  system_name = get_system_name(host)
  xpath_query = "//tr[td[contains(.,'#{system_name}')]]//button[@title = 'Reject']"
  raise "xpath: #{xpath_query} not found" unless find(:xpath, xpath_query).click
end

When(/^I delete "([^"]*)" from the Rejected section$/) do |host|
  system_name = get_system_name(host)
  xpath_query = "//tr[td[contains(.,'#{system_name}')]]//button[@title = 'Delete']"
  raise "xpath: #{xpath_query} not found" unless find(:xpath, xpath_query).click
end

When(/^I see "([^"]*)" fingerprint$/) do |host|
  node = get_target(host)
  salt_call = $product == 'Uyuni' ? "venv-salt-call" : "salt-call"
  output, _code = node.run("#{salt_call} --local key.finger")
  fing = output.split("\n")[1].strip!
  raise "Text: #{fing} not found" unless has_content?(fing)
end

When(/^I accept "([^"]*)" key$/) do |host|
  system_name = get_system_name(host)
  xpath_query = "//tr[td[contains(.,'#{system_name}')]]//button[@title = 'Accept']"
  raise "xpath: #{xpath_query} not found" unless find(:xpath, xpath_query).click
end

When(/^I refresh page until I see "(.*?)" hostname as text$/) do |minion|
  within('#spacewalk-content') do
    step %(I wait until I see the name of "#{minion}", refreshing the page)
  end
end

When(/^I refresh page until I do not see "(.*?)" hostname as text$/) do |minion|
  within('#spacewalk-content') do
    step %(I wait until I do not see the name of "#{minion}", refreshing the page)
  end
end

When(/^I list packages with "(.*?)"$/) do |str|
  find('input#package-search').set(str)
  find('button#search').click
end

When(/^I change the state of "([^"]*)" to "([^"]*)" and "([^"]*)"$/) do |pkg, state, instd_state|
  # Options for state are Installed, Unmanaged and Removed
  # Options for instd_state are Any or Latest
  # Default if you pick Installed is Latest
  find("##{pkg}-pkg-state").select(state)
  if !instd_state.to_s.empty? && state == 'Installed'
    find("##{pkg}-version-constraint").select(instd_state)
  end
end

When(/^I click undo for "(.*?)"$/) do |pkg|
  find("button##{pkg}-undo").click
end

When(/^I click apply$/) do
  find('button#apply').click
end

When(/^I click save$/) do
  find('button#save').click
end

# salt-ssh steps
When(/^I uninstall Salt packages from "(.*?)"$/) do |host|
  target = get_target(host)
  pkgs = $product == 'Uyuni' ? "venv-salt-minion" : "salt salt-minion"
  if %w[sle_minion ssh_minion sle_client].include?(host)
    target.run("test -e /usr/bin/zypper && zypper --non-interactive remove -y #{pkgs}", check_errors: false)
  elsif %w[ceos_minion].include?(host)
    target.run("test -e /usr/bin/yum && yum -y remove #{pkgs}", check_errors: false)
  elsif %w[ubuntu_minion].include?(host)
    pkgname = "salt-common salt-minion" if $product != 'Uyuni'
    target.run("test -e /usr/bin/apt && apt -y remove #{pkgs}", check_errors: false)
  end
end

When(/^I install Salt packages from "(.*?)"$/) do |host|
  target = get_target(host)
  pkgs = $product == 'Uyuni' ? "venv-salt-minion" : "salt salt-minion"
  if %w[sle_minion ssh_minion sle_client].include?(host)
    target.run("test -e /usr/bin/zypper && zypper --non-interactive install -y #{pkgs}", check_errors: false)
  elsif %w[ceos_minion].include?(host)
    target.run("test -e /usr/bin/yum && yum -y install #{pkgs}", check_errors: false)
  elsif %w[ubuntu_minion].include?(host)
    pkgs = "salt-common salt-minion" if $product != 'Uyuni'
    target.run("test -e /usr/bin/apt && apt -y install #{pkgs}", check_errors: false)
  end
end

When(/^I enable repositories before installing Salt on this "([^"]*)"$/) do |host|
  step %(I enable repository "tools_additional_repo" on this "#{host}" without error control)
end

When(/^I disable repositories after installing Salt on this "([^"]*)"$/) do |host|
  step %(I disable repository "tools_additional_repo" on this "#{host}" without error control)
end

# minion bootstrap steps
Then(/^I run spacecmd listevents for "([^"]*)"$/) do |host|
  system_name = get_system_name(host)
  $server.run('spacecmd -u admin -p admin clear_caches')
  $server.run("spacecmd -u admin -p admin system_listevents #{system_name}")
end

When(/^I enter "([^"]*)" password$/) do |host|
  raise "#{host} minion password is unknown" unless %w[kvm_server xen_server].include?(host)
  step %(I enter "#{ENV['VIRTHOST_KVM_PASSWORD']}" as "password") if host == "kvm_server"
  step %(I enter "#{ENV['VIRTHOST_XEN_PASSWORD']}" as "password") if host == "xen_server"
end

When(/^I perform a full salt minion cleanup on "([^"]*)"$/) do |host|
  node = get_target(host)
  pkgs = $product == 'Uyuni' ? "venv-salt-minion" : "salt salt-minion"
  if host.include? 'ceos'
    node.run("yum -y remove --setopt=clean_requirements_on_remove=1 #{pkgs}", check_errors: false)
  elsif (host.include? 'ubuntu') || (host.include? 'debian')
    pkgs = "salt-common salt-minion" if $product != 'Uyuni'
    node.run("apt-get --assume-yes remove #{pkgs} && apt-get --assume-yes purge #{pkgs} && apt-get --assume-yes autoremove", check_errors: false)
  else
    node.run("zypper --non-interactive remove --clean-deps -y #{pkgs} spacewalk-proxy-salt", check_errors: false)
  end
  if $product == 'Uyuni'
    node.run('rm -Rf /root/salt /var/cache/venv-salt-minion /run/venv-salt-minion /var/venv-salt-minion.log /etc/venv-salt-minion /var/tmp/.root*', check_errors: false)
  else
    node.run('rm -Rf /root/salt /var/cache/salt/minion /var/run/salt /run/salt /var/log/salt /etc/salt /var/tmp/.root*', check_errors: false)
  end
  step %(I disable the repositories "tools_update_repo tools_pool_repo" on this "#{host}" without error control)
end

When(/^I install a salt pillar top file for "([^"]*)" with target "([^"]*)" on the server$/) do |file, host|
  system_name = host == "*" ? "*" : get_system_name(host)
  script = "base:\n" \
            "  '#{system_name}':\n" \
            "    - '#{file}'\n"
  path = generate_temp_file('top.sls', script)
  inject_salt_pillar_file(path, 'top.sls')
  `rm #{path}`
end

When(/^I install a salt pillar file with name "([^"]*)" on the server$/) do |file|
  source = File.dirname(__FILE__) + '/../upload_files/' + file
  inject_salt_pillar_file(source, file)
end

When(/^I delete a salt "([^"]*)" file with name "([^"]*)" on the server$/) do |type, file|
  case type
  when 'state'
    path = "/srv/salt/" + file
  when 'pillar'
    path = "/srv/pillar/" + file
  else
    raise 'Invalid type.'
  end
  return_code = file_delete($server, path)
  raise 'File Deletion failed' unless return_code.zero?
end

When(/^I install "([^"]*)" to custom formula metadata directory "([^"]*)"$/) do |file, formula|
  source = File.dirname(__FILE__) + '/../upload_files/' + file
  dest = "/srv/formula_metadata/" + formula + '/' + file

  $server.run("mkdir -p /srv/formula_metadata/" + formula)
  return_code = file_inject($server, source, dest)
  raise 'File injection failed' unless return_code.zero?
  $server.run("chmod 644 " + dest)
end

When(/^I kill remaining Salt jobs on "([^"]*)"$/) do |minion|
  system_name = get_system_name(minion)
  output, _code = $server.run("salt #{system_name} saltutil.kill_all_jobs")
  if output.include?(system_name) && output.include?('Signal 9 sent to job')
    log output
  end
end

When(/^I set "([^"]*)" as NIC, "([^"]*)" as prefix, "([^"]*)" as branch server name and "([^"]*)" as domain$/) do |nic, prefix, server_name, domain|
  cred = "--api-user admin --api-pass admin"
  dhcp = "--dedicated-nic #{nic} --branch-ip #{net_prefix}#{ADDRESSES['proxy']} --netmask 255.255.255.0 --dyn-range #{net_prefix}#{ADDRESSES['range begin']} #{net_prefix}#{ADDRESSES['range end']}"
  names = "--server-name #{server_name} --server-domain #{domain} --branch-prefix #{prefix}"
  output, return_code = $server.run("retail_branch_init #{$proxy.full_hostname} #{dhcp} #{names} #{cred}")
  raise "Command failed with following output: #{output}" unless return_code.zero?
end
