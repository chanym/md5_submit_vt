#!/usr/bin/ruby

puts "\n** Getting all the files md5sum and check against Virustotal **\n\n"

if ARGV.length != 1 || !File.directory?(ARGV[0])
	puts "Usage - ./md5_submit_vt.rb [dir]"
	puts "\nExample - ./md5_submit_vt.rb <directory>"
	exit
end

require 'mechanize'
file = Hash.new

#Please enter your non premium virustotal api key here
apikey = ''

Dir.entries(ARGV[0]).each do |f|
	if (f !~ /^\.$/) && (f !~ /^\.\.$/)
		if ARGV[0] !~ /\/$/
			ARGV[0] = ARGV[0] + '/'
		end
		fullpath = ARGV[0] + f
		digest = `md5sum '#{fullpath}'`
		file[f] = digest.split(" ")[0]
	end
end 

agent = Mechanize.new

count = 0
total = 0
file.each_key do |key|
	if count < 4
		puts "\n----- #{key} -----\n"
		page = agent.get("http://www.virustotal.com/vtapi/v2/file/report?resource=#{file[key]}&apikey=#{apikey}")
		page.body.split(',').each do |x|
			x.gsub!('{', '')
			x.gsub!('"', '')  
			x.gsub!('}', '')  
			x.gsub!('[', "\n ")  
			x.gsub!(']', '')
			x.gsub!('resolutions:', '')
			x.gsub!(/^asn:/, ' asn:')  
			puts x
		end
		puts "\n--------- end -----------\n"
		count += 1
	else
		sleep 60
		count = 0
		redo
	end
end
