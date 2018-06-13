APACHE_HOME= attribute(
  'apache_home',
  description: 'location of apache home directory',
  default: '/etc/httpd'
)

APACHE_CONF_DIR= attribute(
  'apache_home',
  description: 'location of apache conf directory',
  default: '/etc/httpd/conf'
)

only_if do
  service('nfs').running?
end


control "V-2226" do
  title "Web content directories must not be anonymously shared."
  desc  "Sharing web content is a security risk when a web server is involved.
Users accessing the share anonymously could experience privileged access to the
content of such directories. Network sharable directories expose those
directories and their contents to unnecessary access. Any unnecessary exposure
increases the risk that someone could exploit that access and either
compromises the web content or cause web server performance problems."
  impact 0.5
  tag "gtitle": "WG210"
  tag "gid": "V-2226"
  tag "rid": "SV-33022r1_rule"
  tag "stig_id": "WG210 A22"
  tag "fix_id": "F-2275r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "ia_controls": "ECCD-1, ECCD-2"
  tag "check": "To view the DocumentRoot enter the following command:

grep \"DocumentRoot\" /usr/local/apache2/conf/httpd.conf

To view the ServerRoot enter the following command:

grep \"serverRoot\" /usr/local/apache2/conf/httpd.conf

Note the location following the DocumentRoot and ServerRoot directives.

Enter the following commands to determine if file sharing is running:

ps -ef | grep nfs, ps -ef | grep smb

If results are returned, determine the shares and confirm they are not in the
same directory as listed above, If they are, this is a finding. "
  tag "fix": "Remove the shares from the applicable directories."

  begin
    # had to do some regex'ing to remove extra back slashes
    doc_root = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").DocumentRoot.map!{ |element| element.gsub(/"/, '') }
    srv_root = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").ServerRoot.map!{ |element| element.gsub(/"/, '') }
    nfs_doc_root = command("showmount -e | grep #{doc_root[0]}")
    nfs_srv_root = command("showmount -e | grep #{srv_root[0]}")

    describe nfs_doc_root do
      its('stdout') { should_not include doc_root[0] }
    end

    describe nfs_srv_root do
      its('stdout') { should_not include srv_root[0] }
    end
  end
end
