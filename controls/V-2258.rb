APACHE_HOME= attribute(
  'apache_home',
  description: 'location of apache home directory',
  default: '/etc/httpd'
)

APACHE_CONF_DIR= attribute(
  'apache_conf_dir',
  description: 'location of apache conf directory',
  default: '/etc/httpd/conf'
)

APACHE_LOG_DIR= attribute(
  'apache_log_dir',
  description: 'location of apache log directory',
  default: '/etc/httpd/logs'
)

control "V-2258" do
  title "Web client access to the content directories must be restricted to
read and execute."
  desc  "Excessive permissions for the anonymous web user account are one of
the most common faults contributing to the compromise of a web server. If this
user is able to upload and execute files on the web server, the organization or
owner of the server will no longer have control of the asset."
  impact 0.7
  tag "gtitle": "WG290"
  tag "gid": "V-2258"
  tag "rid": "SV-33027r1_rule"
  tag "stig_id": "WG290 A22"
  tag "fix_id": "F-29342r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "ia_controls": "ECLP-1"
  tag "check": "To view the value of Alias enter the following command:

grep \"Alias\" /usr/local/apache2/conf/httpd.conf

Alias
ScriptAlias
ScriptAliasMatch

Review the results to determine the location of the files listed above.

Enter the following command to determine the permissions of the above file:

ls -Ll /file-path

The only accounts listed should be the web administrator, developers, and the
account assigned to run the apache server service.
If accounts that don’t need access to these directories are listed, this is a
finding.
If the permissions assigned to the account for the Apache web server service is
greater than Read & Execute (R_E), this is a finding."
  tag "fix": "Assign the appropriate permissions to the applicable directories
and files using the chmod command."

  script_alias = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").ScriptAlias.map!{ |element| element.gsub(/"/, '') }[0].split(" ")[1]

  describe directory(script_alias) do
    its('owner') { should cmp 'apache' }
  end

  describe directory(script_alias) do
    its('mode') { should cmp '0500' }
  end
end
