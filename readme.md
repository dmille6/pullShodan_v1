# Pull Shodan v1:
### Just simple script to run a query on teh shodan.io database and pull all new entries for a state. (you can change the query to anything you want)

# Bash Script:
### uses the shodan.io CLI to run the query and save the data in a json.
*i use a cron job to run this script every night at midnight

# parseShodan.py:
### parses a folder of these exported json files and dumps the data into elasticsearch