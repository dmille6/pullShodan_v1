########################## pullShodanLA.sh #########################
# You'll need to download and install the shodan CLI for this simple
# script, you can download/install it here:
# https://cli.shodan.io/

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