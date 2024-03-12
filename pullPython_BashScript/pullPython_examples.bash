########################## pullShodanLA.sh #########################
# You'll need to download and install the shodan CLI for this simple
# script, you can download/install it here:
# https://cli.shodan.io/
####################################################################
# script gets the year-month-day and assigns it to the variable 'd'
# : shodan download --limit -1 la-$d country:us state:la
# : download all : --limit -1
# : filename: la-$d : Example: la-11-01-2024.json
# : query: country:us state:la
###########################################################
# this full download takes 6-8 hours to download
###########################################################
d=$(date +%Y-%m-%d)
sudo /usr/local/bin/shodan download --limit -1 la-$d country:us state:la
gzip -d *.gz
###########################################################

###########################################################
# this script will pull only the new entries in the last 24 hours/1 day
# takes about 5 min to run
###########################################################
d=$(date +%Y-%m-%d-%s)
yd=$(date --date="yesterday" +"%Y-%m-%d")
sudo /usr/local/bin/shodan download --limit -1 la-$d country:us state:la after:$yd
gzip -d *.gz
###########################################################


######## Usage:
# i put this script on very small linux server (ubuntu) and use a cron job to run it every
# night at midnight. these files are put in a folder.. then i use a parser to parse all the
# json files into something useful.
########################
# Example chron job: (runs at midnight every night)
# cronrab -e # opens the cron configuration file
#
# Example Configuration file:
# For more information see the manual pages of crontab(5) and cron(8)
#
# m h  dom mon dow   command
# 0 0 * * * /usr/bin/bash /data/pullShodanLA.sh
#######################
