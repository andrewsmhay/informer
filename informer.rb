#!/usr/bin/env ruby
require 'damerau-levenshtein'
require 'passphrase_entropy'

commands = []
ARGV.each {|arg| commands << arg}
fqdn = []
hostname = []
host = []
hh = []
big_host_list = []
whois = []

dl = DamerauLevenshtein
pe = PassphraseEntropy.new(File.read("/usr/share/dict/words"))
host_list = "./data/hosts.txt" # http://ha.ckers.org/fierce/hosts.txt
results = "./results"

IO.foreach(host_list) do |hlist|
  big_host_list << hlist.chomp
end

IO.foreach(ARGV[1]) do |x|
  fqdn << x.chomp
  hostname << x.chomp.split('.')
end

IO.foreach(ARGV[1]) do |xx|
  whois << xx.chomp
end

a = 0
b = 0
c = fqdn.count
n = hostname.count
i = 0
j = 0

begin
  host << hostname[i].values_at(0)
  i += 1
end until i >= n

host.each do |hoster|
  hoster.each do |h|
    hh << h
  end
end

write_dir = ARGV[1].gsub(/data\//, '')

hostname.clear
if ARGV[0] == "-d" #distance
  f = File.open(results+'/'+write_dir+'_distance.csv', 'a+')
  f.puts "Target,Comparison,Distance.DL,Distance.L,Distance.BR"
  hh.each do |y|
    hh.each do |z|
      if y != z
        dla = dl.distance(y.to_s, z.to_s) # Damerau Levenshtein algorithm
        la = dl.distance(y.to_s, z.to_s, 0) # Levensthein algorithm
        br = dl.distance(y.to_s, z.to_s, 2) # Boehmer & Rees modification
        f.puts y.to_s+","+z.to_s+","+dla.to_s+","+la.to_s+","+br.to_s
      end
    end
  end
  f.close
elsif ARGV[0] == "-c" #character
  f = File.open(results+'/'+write_dir+'_character.csv', 'a+')
  f.puts "Target,Length,Lowerchar,Upperchar,Numericchar,Entropy"
  hh.each do |y|
    ent = pe.entropy(y.to_s)
    leny = y.to_s.length
    lowcase = y.to_s.count('/[a-z]/')
    upcase = y.to_s.count('/[A-Z]/')
    numcase = y.to_s.count('/[0-9]/')
    f.puts y.to_s+","+leny.to_s+","+lowcase.to_s+","+upcase.to_s+","+numcase.to_s+","+ent.to_s
  end
  f.close
elsif ARGV[0] == "-h" #common host info
  f = File.open(results+'/'+write_dir+'_common_host.csv', 'a+')
  f.puts "Target,Length,Lowerchar,Upperchar,Numericchar,Entropy"
  big_host_list.each do |y|
    ent = pe.entropy(y.to_s)
    leny = y.to_s.length
    lowcase = y.to_s.count('/[a-z]/')
    upcase = y.to_s.count('/[A-Z]/')
    numcase = y.to_s.count('/[0-9]/')
    f.puts y.to_s+","+leny.to_s+","+lowcase.to_s+","+upcase.to_s+","+numcase.to_s+","+ent.to_s
  end
  f.close
elsif ARGV[0] == "-w" #whois

  end
  f.close
else puts "[+] Derrrrrrp..." 
end

