"""Simple dxx rebirth game tracker bot
   for http://dxxtracker.reenigne.net/
"""
import fnmatch
import time
import urllib.request
import json

__info__ = {
    "Author": "derhass",
    "Version": "0.9.9",
    "Dependencies": [
        "_timer"
    ]
}

#############################################################################
# DECODE SOME OF THE NUMERICAL FIELDS                                       #
#############################################################################

modes={
	'0':'Anarchy',
	'1':'Team Anarchy',
	'2':'Robo Anarchy',
	'3':'Cooperative',
	'4':'Capture the Flag',
	'5':'Hoard',
	'6':'Team Hoard',
	'7':'Bounty'
}

difficulties={
	'0':'Trainee',
	'1':'Rookie',
	'2':'Hotshot',
	'3':'Ace',
	'4':'Insane'
}

status_codes={
	'0':'Menu',
	'1':'Playing',
	'2':'Browsing',
	'3':'Waiting',
	'4':'Starting',
	'5':'EndLevel'
}

def get_by_dict(value,d):
	if value in d:
		return d[value]
	return value

def getd(game,attr):
	if attr in game:
		return game[attr]
	print('game attr unknown: ',attr)
	return '[UNKNOWN]'

#############################################################################
# PARSER FSM FOR TRACKER RESPONSES                                          #
#############################################################################

# NOTE:
# One might argue that the the dxx-rebirth tracker responds in a
# format wich fits the python syntax: a list of dicts, so one could simply
# do games=eval(response). However, there are two main issues with that:
#  a) The escaping is subtly different (look at the "players" field)
#  b) Randomly executing some code we found on a website might not be a good
#     idea. We want to avoid the possibility of code injection here. So using
#     this FSM should be a safe choice.
#     We are now using this parser even for specifying the extended @games
#     filter, so better be very careful
#

# the actions for the FSM		
def clear_game(fsm,c):
	fsm.game={}
def clear_key(fsm,c):
	fsm.key=''
	fsm.value=''
def clear_value(fsm,c):
	fsm.value=''
def add_key(fsm,c):
	fsm.key += c
def add_value(fsm,c):
	fsm.value += c
def add_attribute(fsm,c):
	fsm.game[fsm.key]=fsm.value
def add_game(fsm,c):
	if 'mode' in fsm.game:
		fsm.game['mode']=get_by_dict(fsm.game['mode'],modes)
	if 'difficulty' in fsm.game:
		fsm.game['difficulty']=get_by_dict(fsm.game['difficulty'],difficulties)
	if 'status' in fsm.game:
		fsm.game['status']=get_by_dict(fsm.game['status'],status_codes)
	fsm.games.append(fsm.game)

# the FSM state transitions
# {
#  state: ( default_transition, default_action, { symbol: (transition, action),
#                                                 symbol: (transition, action),
#                                                 ... } ),
#  state: ...
#}
fsm={
	'Init': ( None, None,	{      '[': ('SearchGame', clear_game) } ),
	'SearchGame': (None, None, {   '{': ('SearchKey', None),
		       		       ']': ('End',None) } ),
	'SearchKey': (None, None, {    '"': ('Key', clear_key),
		       		       ']': ('Error', None),
				       ':': ('SearchValue', clear_value),
				       '}': ('SearchNextGame', add_game) } ),
	'Key': (None, add_key, {      '\\': ('KeyEscaped', None),
		       		       '"': ('SearchColon', None) } ),
	'KeyEscaped': ('Key', add_key, {} ),
	'SearchColon': (None, None, {  ':': ('SearchValue', None),
		       		       ']': ('Error', None),
				       ',': ('SearchKey', add_attribute),
				       '}': ('SearchNextGame', add_game)} ),
	'SearchValue': (None, None, {  '"': ('Value', clear_value),
		       		       ']': ('Error', None),
				       ',': ('SearchKey', add_attribute),
				       '}': ('SearchNextGame', add_game),
				       ':': ('Error', None) } ),
	'Value': (None, add_value, {  '\\': ('ValueEscaped', None),
		       		       '"': ('NextKey', add_attribute) } ),
	'ValueEscaped': ('Value', add_value, {} ),
	'NextKey': (None, None, {      ',': ('SearchKey', clear_key),
		       		       '}': ('SearchNextGame', add_game),
				       ']': ('Error', None) } ),
	'SearchNextGame': (None,None, {',': ('SearchGame', clear_game),
		       		       ']': ('End', None),
				       ':': ('Error', None),
				       '}': ('Error', None),
				       '{': ('Error', None),
				       '[': ('Error', None) } ),
	'End': (None, None, {} ),
	'Error': (None, None, {} )
}
		
# the FSM code itself 
class parser_fsm:
	def __init__(self,rules):
		self.rules=rules
		self.reset()
		self.key=''
		self.value=''

	def reset(self):
		self.state='Init'
		self.games=list()
		self.status='OK'

	def process_symbol(self,c):
		if self.state in self.rules:
			transitions=self.rules[self.state]
			if c in transitions[2]:
				transition=transitions[2][c]
				if transition[1]:
					transition[1](self,c)
				if transition[0]:
					self.state=transition[0]
			else:
				if transitions[1]:
					transitions[1](self,c)
				if transitions[0]:
					self.state=transitions[0]
		else:
			print('No transitions for state	%s',self.state)
			self.status='INVALID_STATE'

	def process(self,response):
		self.reset()
		for c in response:
			self.process_symbol(c)
		if self.state != 'End':
	 		self.status='PARSE_ERROR'	 

#############################################################################
# FUNCTIONS FOR HANDLING GAME DESCRIPTIONS                                  #
#############################################################################

# check if a given game matches the attribute dict
def game_matches_wildcard(game,attr):
	for a in attr:
		if a in game:
			if not fnmatch.fnmatchcase(game[a],attr[a]):
				return False
		else:
			return False
	# if we got here, every attr matched
	return True

# check if a given game matches the attribute dic
def game_matches(game,attr):
	for a in attr:
		if a in game:
			if game[a] != attr[a]:
				return False
		else:
			return False
	# if we got here, every attr matched
	return True

# filter list of games by the specified attributes
# elemets of the list are supposed to be attr dicts
# a game is matched if ANY of the dicts matches	
def filter_games_attr_list(games, listattr):
	l=list()
	for game in games:
		match=False
		for attr in listattr:
			if game_matches_wildcard(game,attr):
				match=True
		if match:		
			l.append(game)
	return l

# filter list of games by the specified attributes
# only on dict of attributes is used as input	
def filter_games_attr(games, attr):
	if len(attr) < 1:
		# filter is empty
		return games
	l=list()
	for game in games:
		if game_matches_wildcard(game, attr):
			l.append(game)
	return l

# filter list of games by the specified attributes
def filter_games(games, arg):
	attr={}
	if len(arg) < 1:
		# the argument is empty
		return filter_games_attr(games,attr)
	if arg[0] == '[':
		# extended filter syntax:
		# specify a list of attrybute dicts
		parser=parser_fsm(fsm)
		parser.process(arg)
		if parser.status == 'OK':
			return filter_games_attr_list(games,parser.games)
		else:
			raise Exception
	# default case: simple syntax 
	# attributes is a list of key:value;key:value;... pairs
	for p in arg.split(';'):
		q=p.split(':')
		if len(q)==2:
			attr[q[0]]=q[1]
		else:
			raise Exception
	return filter_games_attr(games,attr)

# check if the list "games" contains
# a game which matches all of the attributes
def known_game_by_attr(games, attributes):
	for game in games:
		if game_matches(game,attributes):
			return game
	return None

# check if the list "games" contains a game
# which matches "game" on all specified attributes 	
def known_game_same_attr(games, game, attrlist):
	attributes={}
	for a in attrlist:
		if a in game:
			attributes[a]=game[a]
	return known_game_by_attr(games,attributes)

# Extract all the requested attributes from a game
# And return it as a string
def game_desc_by_attrlist(game, attrlist):
	desc=''
	i=0
	for attr in attrlist:
		if i > 0:	
			desc = desc + ' - '
		desc = desc + getd(game, attr)	
		i=i+1
	return desc

# check if we already know about a game	
# we identify a game by a set of certain attributes defined
# here. We do not want to detect a game as new if just the
# number of players changed, or something like that...	
def known_game(games, game):
	attr=('game','ip','port','version','name','missionname','missiontitle',
	      'missionlevel','mode','difficulty')
	return known_game_same_attr(games, game, attr)

# make a string from a game description	
# used when we detect a new games
def game_string_new(game):
	g='\x0312NEW GAME\x0302 %sx-%s: %s %s in %s(%s) at %sx://%s:%s (%s)\x03 ' % \
		(getd(game,'game'), getd(game,'version'),
		 getd(game,'name'), getd(game,'mode'),
		 getd(game,'missiontitle'), getd(game,'missionlevel'),
		 getd(game,'game'), getd(game,'ip'), getd(game,'port'),
		 getd(game,'country'))
	return g

# make a string from a game description	
# used when we detect that a game has ended
def game_string_end(game):
	g='\x0314game has ended %sx %s %s in %s(%s)\x03 ' % \
		(getd(game,'game'),
		 getd(game,'name'), getd(game,'mode'),
		 getd(game,'missiontitle'), getd(game,'missionlevel'))
	return g


# make a string from a game description	
# used when we list the games	
def game_string_list(game):
	g='\x02%sx-%s\x02: \x02%s\x02 \x02%s\x02 in \x02%s\x02(\x02%s\x02) at \x02%sx://%s:%s\x02 (\x02%s\x02), players: \x02%s\x02, difficulty: \x02%s\x02, status: \x02%s\x02, disovered at \x02%s\x02' % \
		(getd(game,'game'), getd(game,'version'),
		 getd(game,'name'), getd(game,'mode'),
		 getd(game,'missiontitle'), getd(game,'missionlevel'),
		 getd(game,'game'), getd(game,'ip'), getd(game,'port'),
		 getd(game,'country'),
		 getd(game,'players'), getd(game,'difficulty'),
		 getd(game,'status'), getd(game,'discovered'))
	return g

	
#############################################################################
# GEOLOCATION                                                               #
#############################################################################

def get_geo_info(ip):
	try:
		r='http://freegeoip.net/json/%s' % ip
		req=urllib.request.Request(r)
		response=urllib.request.urlopen(req).read()
		decode=response.decode('ascii')
		info=json.loads(decode)
	except:
		info={}
	return info	

def get_country(ip):
	try:
		info=get_geo_info(ip)
		#cc=info['country_code'];
		#if 'region_code' in info:
		#	cc += '/' + info['region_code']
		cc=info['country_name'];
		if 'region_name' in info:
			cc += '/' + info['region_name']
	except:
		cc='[UNKNOWN]'
	return cc

#############################################################################
# OBJECT TO ENCAPSULATE THE TRACKER                                         #
#############################################################################

# encapsulate communication with the tracker,
# keep a list of currently known games		
class dxxtracker_client:
	def __init__(self):
		self.url='' # the tracker URL
		self.games=list() # list of running games
		self.parser=parser_fsm(fsm) # parser FSM
		self.failed=False;
		self.running=False;
		self.lost=False;
		self.recover=False;
		self.poll_count=0;
		self.request_error=0;
		self.parse_error=0;
		self.fake=False;
		self.locate_ip=True;
		self.cur_time='';
		self.now=time.time()
		self.history=list()
		self.history_seconds=7*24*60*60
		self.gamecount=0
		# custom headers for HTTP request
		self.headers={"User-Agent": "Schongo Bot dxxtracker client"}

	def set_url(self,url):
		self.url=url

	def set_fake(self,arg):
		if arg=='True':
			self.fake=True
		else:
			self.fake=False

	def set_locate_ip(self,arg):
		if arg=='True':
			self.locate_ip=True
		else:
			self.locate_ip=False

	def set_history_seconds(self,arg):
		self.history_seconds=arg	

	def fail(self,reason):
		if not self.failed:
			self.failed=True
			self.lost=True
	
	def success(self):
		if self.failed:
			self.failed=False;
			self.recover=True

	# some captured description for debugging
	def query_fake(self):		
		response=b'[{"game":"d2","ip":"82.32.244.126","port":"42426","version":"0.57.3","name":"rangers scored","missionname":"Pyromani","missiontitle":"Pyromania","missionlevel":"1","mode":"0","difficulty":"3","status":"1","players":"5\\/8"},{"game":"d1","ip":"68.205.92.104","port":"42424","version":"0.57.3","name":"DF\'s Game","missionname":"seven","missiontitle":"Seven","missionlevel":"1","mode":"0","difficulty":"3","status":"1","players":"2\\/8"},{"game":"d2","ip":"178.82.200.41","port":"42424","version":"0.57.3","name":"getin","missionname":"Neptune","missiontitle":"Neptune","missionlevel":"1","mode":"0","difficulty":"2","status":"1","players":"1\\/6"},{"game":"d1","ip":"77.251.175.48","port":"42424","version":"0.57.3","name":"blue_01-DTF","missionname":false,"missiontitle":"Descent: First Strike","missionlevel":"1","mode":"3","difficulty":"2","status":"5","players":"3\/4"}]'
		return response.decode('ascii')

	def query(self):
		self.poll_count += 1
		self.now=time.time()
		self.cur_time=time.strftime("%d %b %Y %H:%M:%S GMT", time.gmtime())
		if self.fake:
			return self.query_fake()
		try:
			req=urllib.request.Request(self.url,
		       				   headers=self.headers)
			response=urllib.request.urlopen(req).read()
			decoded=response.decode('ascii')
		except:
			self.request_error += 1
			decoded='*FAILED REQUEST'
		return decoded

	def enrich_gamedata(self,game):
		game['discovered']=self.cur_time;
		game['timestamp']=self.now;
		if self.locate_ip:
			if 'ip' in game:
				game['country']=get_country(game['ip'])
			else:
				game['country']='[UNKNOWN]'
		return game

	def clean_history(self):
		while len(self.history) > 0 and self.now - self.history[0]['timestamp'] > self.history_seconds:
			del self.history[0]

	def charts(self,attributes,cnt):
		histogram=dict()
		for g in self.history:
			attr=game_desc_by_attrlist(g,attributes)
			if attr in histogram:
				histogram[attr]=histogram[attr]+1
			else:
				histogram[attr]=1
		l=list()
		for e in histogram:
			l.append((e,histogram[e]))
		l.sort(key=lambda x: x[1],reverse=True)	
		if len(l)>cnt:
			l=l[:cnt] 
		return l	

	def update(self,response):
		self.lost=False
		self.recover=False
		new_games=list()
		vanished_games=list()
		if response == '*FAILED REQUEST':
			self.fail('failed to get data from tracker')
			return (new_games, vanished_games);		
		try:
			self.parser.process(response)
			if self.parser.status != 'OK':
				raise Exception
			# search new games
			games=list()
			for g in self.parser.games:
				g['last_seen']=self.cur_time;
				old_game=known_game(self.games, g)
				if old_game == None:
					g=self.enrich_gamedata(g)
					new_games.append(g)
					self.history.append(g)
					self.gamecount=self.gamecount+1
					games.append(g)
				else:
					# old_game is already enriched
					games.append(old_game)
			# search vanished games
			for g in self.games:
				if not known_game(self.parser.games, g):
					vanished_games.append(g)
			# update current list of games
			self.games=games
			self.success()
			# remove old games from the history
			self.clean_history()
		except:
			self.parse_error += 1
			self.fail('parse error')
		return (new_games, vanished_games)

#############################################################################
# GLOBAL OBJECTS                                                            #
#############################################################################

# create the global dxxtracker client object		
client=dxxtracker_client()

#############################################################################
# HELPER FUNCTIONS FOR THE BOT                                              #
#############################################################################

# list all games	
def do_list(ctx,args):
	print('listing games')
	if len(client.games) == 0:
		ctx.reply('sorry, there are currently no games running')
		return False
	try:
			games=filter_games(client.games,args)
	except:
		ctx.reply('sorry, I did not understand your request')
		return False
	for g in games:
		ctx.reply(game_string_list(g))
	if len(games) == 0:
		ctx.reply('sorry, could not find any games matching your query')
	return True	

# request new data from the tracker and parse respone
def do_update(ctx):
	(n,v)=client.update(client.query())
	if client.lost:
	 	print ('Failed to get tracker data.')
	 	ctx.reply('Failed to get tracker data. I will inform you when tracker seems available again.')
	if client.recover:
	 	print ('Tracker seems to be available again.')
	 	ctx.reply('Tracker seems to be available again.')
	 	
	for g in v:
		ctx.reply(game_string_end(g))	
	for g in n:
		ctx.reply(game_string_new(g))
	if client.failed:
 		print ('update: failed to get data from tracker')
	print('update: found %d new games, %d closed games' % (len(n),len(v)) )	

# request charts
def do_charts(ctx,args):
	arg=args.split()
	if len(arg)>0:
		attributes=[arg[0]]
	else:
		attributes=['missiontitle',"missionlevel","mode"]
	if len(arg)>1:
		cnt=int(arg[1])
	else:
		cnt=5
	l=client.charts(attributes,cnt)
	if (len(l) < 1):
		reply='Sorry, no data for charts request'
	else :
		reply='Top %d by ' % len(l)
		i=1
		for a in attributes:
			if i > 1:
				reply = reply + ' and '
			reply = reply + a
			i=i+1
		reply=reply+':'
		ctx.reply(reply)
		reply=''
		i=1
		for e in l:
			if i > 1:
				reply = reply+'| '
			reply=reply + '%d. %s (%d) ' % (i,e[0],e[1])
			i=i+1
	ctx.reply(reply)	 


# reply with current status	
def do_status(ctx):
	print('status')
	ctx.reply('number of games: current: %d, in history: %d, total: %d' % (len(client.games),len(client.history), client.gamecount)) 
	ctx.reply('number of polls: %d, failed requests: %d, parse errors: %d' % (client.poll_count, client.request_error, client.parse_error))
	if client.failed:
		ctx.reply('tracker seems NOT to be availbale')
	else:
		ctx.reply('tracker seems to be availbale')

#############################################################################
# INTERFACE TO SCHONGO BOT CORE                                             #
#############################################################################

def onLoad():
	print('DXXTRACKER bot initializing')

	client.set_url(cfg.get("url"))
	client.set_fake(cfg.get("fake"))
	client.set_locate_ip(cfg.get("locate_ip"))
	client.set_history_seconds(float(cfg.get("history_seconds")))

	@timer(int(cfg.get("interval")), True)
	def update_timer(ctx):
		do_update(ctx)
		return True

	@command("games")
	def games_cmd(ctx, cmd, args):
		do_list(ctx, args)

	@command("charts")
	def charts_cmd(ctx, cmd, args):
		do_charts(ctx, args)	

	# Update command is now uselsess as the timer is working
	# do not support it as las a user could try to exploit this to
	# flood the tracker with requests from _us_	
	#@command("update")
	#def update_cmd(ctx, cmd, args):
	#	do_update(ctx)    

	@command("status")
	def status_cmd(ctx, cmd, args):
		do_status(ctx)

	# just use the topic hook
	# The server will reply with the current topic when we join
	# and topic changes happen not too often, i guess
	# If we are not yet running, start the timer
	@hook("topic")
	def topic_hook(ctx, arg):
		print('Topic changed to: '+arg)
		if not client.running:
			print('Starting timer')
			ctx.reply('Hi, this is Schongo dxxtrackerbot '+__info__['Version'])
			ctx.reply('polling '+client.url+' every '+cfg.get("interval") + ' seconds')
			ctx.reply('use @games to query the list of currently running games')
			do_update(ctx);
			update_timer.start(ctx);
			client.running=True
