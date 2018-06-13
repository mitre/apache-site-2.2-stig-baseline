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

control "V-2245" do
  title "Each readable web document directory must contain either a default,
home, index, or equivalent file."
  desc  "The goal is to completely control the web users experience in
navigating any portion of the web document root directories. Ensuring all web
content directories have at least the equivalent of an index.html file is a
significant factor to accomplish this end. Also, enumeration techniques, such
as URL parameter manipulation, rely upon being able to obtain information about
the web server’s directory structure by locating directories with default
pages. This practice helps ensure that the anonymous web user will not obtain
directory browsing information or an error message that reveals the server type
and version."
  impact 0.3
  tag "gtitle": "WG170"
  tag "gid": "V-2245"
  tag "rid": "SV-33020r1_rule"
  tag "stig_id": "WG170 A22"
  tag "fix_id": "F-29336r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "ia_controls": "ECAN-1, ECSC-1"
  tag "check": "To view the DocumentRoot value enter the following command:
awk '{print $1,$2,$3}' /usr/local/apache2/conf/httpd.conf|grep -i
DocumentRoot|grep -v '^#'
Note each location following the DocumentRoot string, this is the configured
path(s) to the document root directory(s).
To view a list of the directories and sub-directories and the file index.html,
from each stated DocumentRoot location enter the following commands:
find . -type d
find . -type f -name index.html
Review the results for each document root directory and it's subdirectories. If
a directory does not contain an index.html or equivalent default document, this
is a finding.
"
  tag "fix": "Add a default document to the applicable directories."

  begin
    doc_root = apache_conf("#{APACHE_CONF_DIR}/httpd.conf").DocumentRoot.map!{ |element| element.gsub(/"/, '') }[0]
    root_index = command("find #{doc_root} -name index.html")

    describe root_index do
      its('stdout') { should include 'index.html'}
    end
  end
end
