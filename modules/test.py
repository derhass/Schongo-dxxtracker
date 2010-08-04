"""Example Module to test various new features as they are added.

Feel free to add to them!
"""

def onLoad():

	@timer(15, True)
	def bacon_timer(ctx):
		ctx.reply("Meow!")

	parent_cmd("test")
	parent_cmd("test timer")

	@command("test timer start")
	def cheese_cmd(ctx, cmd, arg, *args):
		ctx.reply("I'm hungry...")
		bacon_timer.start(ctx)

	@command("test timer stop")
	def catnip_cmd(ctx, cmd, arg):
		ctx.reply("Ohh. *nom*")
		bacon_timer.cancel()

	@command("test crash")
	def crash_cmd(ctx, cmd, arg):
		None.dicks()

	@command("test say", 2)
	def say_cmd(ctx, cmd, arg, *args):
		where, what = arg.split(' ', 1)
		IrcContext.fromString(where, ctx).reply("Ohai from %s! %s" % ( ctx.chan, what))

	@hook("message")
	def crash_hook(ctx, msg):
		if msg == "CRASH":
			None.dicks()

	@hook("join")
	def join_hook(ctx):
		if ctx.chan == "#schongo-dev":
			ctx.reply("Welcome!")
	
	@hook("topic")
	def topic_hook(ctx, topic):
		nick = ctx.who.__str__().split('!')[0]
		ctx.reply("%s is a topic changin bitch!" % nick, "Topic Alarm")
	
	
