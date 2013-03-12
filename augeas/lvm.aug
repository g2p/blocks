module LVM =
	autoload xfm

	(* See lvm2/libdm/libdm-config.c for tokenisation;
	 * libdm uses a blacklist but I prefer the safer whitelist approach. *)
	let identifier = /[a-zA-Z0-9_]+/
	let comment = Util.comment

	let comma = del /,[ \t]*/ ", "

	(* strings can contain backslash-escaped dquotes, but I don't know
	 * how to get the message across to augeas *)
	let str = [label "str". Quote.do_dquote (store /[^"]*/)]
	let int = [label "int". store Rx.integer]

	let strlist = [
		  label "strlist"
		. Util.del_str "["
		.([seq "strlist" . str . comma]* . [seq "strlist" . str])?
		. Util.del_str "]"]

	let stripelist = [
		  label "stripelist"
		. Util.del_str "[\n"
		.(Util.indent . str . comma . int . Util.del_str "\n")+
		. Util.indent . Util.del_str "]"]

	let val = str | int | strlist | stripelist

	let assignment = [
		  label "assign"
		. Util.indent
		. Build.key_value_line_comment identifier Sep.space_equal val comment]

	let nonblock =
		  Util.empty
		| comment
		| assignment

	(* Build.block couldn't be reused, because of recursion and
	 * a different philosophy of whitespace handling. *)
	let rec block = [label "block" . [
		  Util.indent . key identifier . Sep.opt_space . Util.del_str "{\n"
		.(nonblock | block)*
		. Util.indent . Util.del_str "}\n"]]

	let lns = (nonblock | block)*

	let filter =
		  incl "/etc/lvm/archive/*.vg"
		. incl "/etc/lvm/backup/*"
		. Util.stdexcl

	let xfm = transform lns filter

