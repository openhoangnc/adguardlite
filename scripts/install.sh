#!/bin/sh

# Sift installation script.
#
# Installs, upgrades or removes Sift -- a drop-in Rust backend for AdGuard
# Home -- as a system service:
#
#	curl -s -S -L https://raw.githubusercontent.com/openhoangnc/sift/main/scripts/install.sh | sh -s -- -v
#
# It is modelled on AdGuard Home's own install.sh, and differs from it in the
# three places where being a drop-in changes what the right thing to do is:
#
#   - an existing installation is UPGRADED rather than refused.  Only the
#     binary is replaced; the config file, the data directory and the unit
#     file are left exactly as they are, because both builds read and write
#     them in the same formats under the same names.
#   - an existing ADGUARD HOME is recognised and taken over in place, for the
#     same reason.  Its binary is kept as AdGuardHome.bak, so going back is a
#     stop, a mv and a start.
#   - the installed version is compared against the release on offer, so
#     running this twice does nothing the second time.
#
# Exit the script if a pipeline fails (-e), prevent accidental filename
# expansion (-f), and consider undefined variables as errors (-u).
set -e -f -u

# Function log is an echo wrapper that writes to stderr if the caller
# requested verbosity level greater than 0.  Otherwise, it does nothing.
log() {
	if [ "$verbose" -gt '0' ]; then
		echo "$1" 1>&2
	fi
}

# Function error_exit is an echo wrapper that writes to stderr and stops the
# script execution with code 1.
error_exit() {
	echo "$1" 1>&2

	exit 1
}

# Function usage prints the note about how to use the script.
usage() {
	echo 'install.sh: usage: [-b base_url] [-C cpu_type] [-h] [-O os] [-o output_dir]' \
		'[-r|-R] [-t tag] [-u|-U] [-v|-V]
	-b base_url   where the release archives live; for testing an unpublished build
	-C cpu_type   cpu type to install for, instead of this machine'"'"'s
	-h            print this and exit
	-O os         operating system to install for, instead of this machine'"'"'s
	-o dir        directory to install into; the default is the running service'"'"'s,
	              or /opt
	-r            reinstall even when the installed version is the one on offer
	-t tag        release tag to install, such as v0.5.0; the default is the latest
	-u            uninstall: remove the binary and the service, keep the config
	              file and the data directory
	-v, -V        turn progress messages on (-v) or off (-V)' 1>&2

	exit 2
}

# Function is_command checks if the command exists on the machine.
is_command() {
	command -v "$1" >/dev/null 2>&1
}

# Function parse_opts parses the options list and validates its combinations.
parse_opts() {
	while getopts "b:C:hO:o:rRt:uUvV" opt "$@"; do
		case "$opt" in
		b)
			base_url="$OPTARG"
			;;
		C)
			cpu="$OPTARG"
			;;
		h)
			usage
			;;
		O)
			os="$OPTARG"
			;;
		o)
			out_dir="$OPTARG"
			;;
		R)
			reinstall='0'
			;;
		r)
			reinstall='1'
			;;
		t)
			tag="$OPTARG"
			;;
		U)
			uninstall='0'
			;;
		u)
			uninstall='1'
			;;
		V)
			verbose='0'
			;;
		v)
			verbose='1'
			;;
		*)
			log "bad option $OPTARG"

			usage
			;;
		esac
	done

	if [ "$uninstall" -eq '1' ] && [ "$reinstall" -eq '1' ]; then
		error_exit 'the -r and -u options are mutually exclusive'
	fi
}

# Function set_os sets the os if needed and validates the value.
set_os() {
	if [ "$os" = '' ]; then
		os="$(uname -s)"
		case "$os" in
		'Darwin')
			os='darwin'
			;;
		'Linux')
			os='linux'
			;;
		*)
			error_exit "unsupported operating system: '$os'
sift publishes binaries for linux and darwin; build from source for anything else"
			;;
		esac
	fi

	case "$os" in
	'darwin' | 'linux')
		# All right, go on.
		;;
	*)
		error_exit "unsupported operating system: '$os'"
		;;
	esac

	log "operating system: $os"
}

# Function set_cpu sets the cpu if needed and validates the value.  The names
# are Go's, because they are the names AdGuard Home's own packages use and the
# ones anybody moving between the two will type.
set_cpu() {
	if [ "$cpu" = '' ]; then
		cpu="$(uname -m)"
		case "$cpu" in
		'x86_64' | 'x86-64' | 'x64' | 'amd64')
			cpu='amd64'
			;;
		'i386' | 'i486' | 'i686' | 'i786' | 'x86')
			cpu='386'
			;;
		'armv6l')
			cpu='armv6'
			;;
		'armv7l' | 'armv8l')
			cpu='armv7'
			;;
		'aarch64' | 'arm64')
			cpu='arm64'
			;;
		*)
			error_exit "unsupported cpu type: $cpu"
			;;
		esac
	fi

	case "$cpu" in
	'amd64' | 'arm64' | 'armv6' | 'armv7' | '386')
		# All right, go on.
		;;
	*)
		error_exit "unsupported cpu type: $cpu"
		;;
	esac

	log "cpu type: $cpu"
}

# download_curl uses curl(1) to download a file.  The first argument is the
# URL.  The second argument is optional and is the output file.
download_curl() {
	if [ "${2:-}" = '' ]; then
		curl -f -L -S -s "$1"
	else
		curl -f -L -S -s -o "$2" "$1"
	fi
}

# download_wget uses wget(1) to download a file.  The first argument is the
# URL.  The second argument is optional and is the output file.
download_wget() {
	wget --no-verbose -O "${2:--}" "$1"
}

# Function set_download_func sets the appropriate function for downloading
# files.
set_download_func() {
	if is_command 'curl'; then
		# Go on and use the default, download_curl.
		return 0
	elif is_command 'wget'; then
		download_func='download_wget'
	else
		error_exit 'either curl or wget is required to install sift via this script'
	fi
}

# Function check_required checks that the software the script itself needs is
# on the machine.  curl or wget is checked by set_download_func.
check_required() {
	for cmd in tar; do
		log "checking $cmd"
		if ! is_command "$cmd"; then
			error_exit "$cmd is required to install sift via this script"
		fi
	done
}

# Function is_root checks for root privileges to be granted.
is_root() {
	if [ "$(id -u)" -eq '0' ]; then
		log 'script is executed with root privileges'

		return 0
	fi

	if is_command "$sudo_cmd"; then
		log 'note that sift requires root privileges to install using this script'

		return 1
	fi

	error_exit 'root privileges are required to install sift using this script
please, restart it with root privileges'
}

# Function rerun_with_root runs the script again with root privileges and
# exits the current one, passing on the configuration it was given.
#
# A script that was piped into a shell has no file to re-run, so it is fetched
# again; one that was saved and run is re-run from where it sits, which is
# also what makes an unpublished copy testable.
rerun_with_root() {
	r='-R'
	if [ "$reinstall" -eq '1' ]; then
		r='-r'
	fi

	u='-U'
	if [ "$uninstall" -eq '1' ]; then
		u='-u'
	fi

	v='-V'
	if [ "$verbose" -eq '1' ]; then
		v='-v'
	fi

	readonly r u v

	log 'restarting with root privileges'

	set -- -b "$base_url" -C "$cpu" -O "$os" "$r" "$u" "$v"
	if [ "$out_dir" != '' ]; then
		set -- "$@" -o "$out_dir"
	fi
	if [ "$tag" != '' ]; then
		set -- "$@" -t "$tag"
	fi

	if [ -f "$0" ] && [ -r "$0" ]; then
		exec "$sudo_cmd" sh "$0" "$@"
	fi

	# Group the download together with an echo, so that if it fails before
	# producing any output, the latter prints an exit command for the
	# following shell to run: an empty input would otherwise exit zero.
	{ "$download_func" "$script_url" || echo 'exit 1'; } \
		| "$sudo_cmd" sh -s -- "$@"

	exit 0
}

# Function service_unit_path prints the path of the init system's unit file
# for the service, whether or not it exists.
service_unit_path() {
	case "$os" in
	'darwin')
		echo '/Library/LaunchDaemons/com.adguard.AdGuardHome.plist'
		;;
	*)
		echo '/etc/systemd/system/AdGuardHome.service'
		;;
	esac
}

# Function installed_bin_from_service prints the path of the binary the
# installed service runs, or nothing if no service is installed.
#
# It is what makes an upgrade land on the installation that is actually
# running rather than on the default directory: AdGuard Home's own installer
# offers -o, and somebody who used it does not want a second copy in /opt.
installed_bin_from_service() {
	unit="$(service_unit_path)"
	[ -r "$unit" ] || return 0

	case "$os" in
	'darwin')
		# The first <string> in ProgramArguments is the binary.
		sed -n 's|.*<string>\(/[^<]*/AdGuardHome\)</string>.*|\1|p' "$unit" \
			| head -1
		;;
	*)
		# ExecStart=/opt/AdGuardHome/AdGuardHome "-s" "run", possibly with one
		# of systemd's prefix characters in front of the path.
		sed -n 's|^ExecStart=[-+!@]*\([^ ]*\).*|\1|p' "$unit" | head -1
		;;
	esac
}

# Function locate_install decides which directory to work in and sets agh_dir
# and agh_bin.
locate_install() {
	if [ "$out_dir" = '' ]; then
		running_bin="$(installed_bin_from_service)"
		if [ "$running_bin" != '' ]; then
			agh_dir="$(dirname "$running_bin")"

			log "the installed service runs $running_bin"
		else
			agh_dir='/opt/AdGuardHome'
		fi
	else
		agh_dir="${out_dir}/AdGuardHome"
	fi

	agh_bin="${agh_dir}/AdGuardHome"
	readonly agh_dir agh_bin

	log "working in $agh_dir"
}

# Function inspect_existing works out what, if anything, is installed already,
# setting existing to one of none, sift, adguardhome or unknown, and
# existing_version to what that binary calls itself.
inspect_existing() {
	existing='none'
	existing_version=''

	[ -x "$agh_bin" ] || return 0

	# A binary that cannot say what it is still counts as something being
	# there; it is just not something to replace without being told to.
	reported="$("$agh_bin" --version 2>/dev/null || true)"
	existing_version="$(
		printf '%s\n' "$reported" \
			| sed -n 's/^[^,]*, version \([^ ][^ ]*\).*/\1/p' \
			| head -1
	)"

	case "$reported" in
	'Sift, version v'*)
		existing='sift'
		;;
	'AdGuard Home, version v'*)
		existing='adguardhome'
		;;
	'AdGuardHome '[0-9]*)
		# Sift before v0.5.0 printed clap's default, which is the package
		# name and a bare semver.
		existing='sift'
		existing_version="v$(printf '%s\n' "$reported" | cut -d ' ' -f 2)"
		;;
	*)
		existing='unknown'
		;;
	esac

	log "found $existing ${existing_version:-of no stated version} in $agh_dir"
}

# Function service_installed reports whether the init system has a unit for
# this installation.
#
# A unit naming some other binary belongs to some other installation: `-o` can
# point anywhere, and stopping or removing a service because it happens to
# share a name with this one is not what was asked for.  A unit whose command
# cannot be read counts as ours, since it is at the path this script writes.
service_installed() {
	[ -f "$(service_unit_path)" ] || return 1

	installed="$(installed_bin_from_service)"

	[ "$installed" = '' ] || [ "$installed" = "$agh_bin" ]
}

# Function stop_service stops the service if one is installed.  A service that
# is not running is not a failure: stopping is only ever done here to get the
# binary out from under it.
stop_service() {
	service_installed || return 0

	log 'stopping the service'

	case "$os" in
	'darwin')
		launchctl unload -w "$(service_unit_path)" 2>/dev/null || true
		;;
	*)
		systemctl stop AdGuardHome 2>/dev/null || true
		;;
	esac
}

# Function service_is_running reports whether the service has a live process.
service_is_running() {
	case "$os" in
	'darwin')
		launchctl list com.adguard.AdGuardHome 2>/dev/null \
			| grep -q '"PID" = [0-9]'
		;;
	*)
		[ "$(systemctl is-active AdGuardHome 2>/dev/null)" = 'active' ]
		;;
	esac
}

# Function rollback puts the previous binary back and starts it, keeping the
# one that failed next to it to be looked at.
rollback() {
	[ -e "${agh_dir}/AdGuardHome.bak" ] || return 1

	stop_service
	mv -f "$agh_bin" "${agh_dir}/AdGuardHome.failed"
	mv -f "${agh_dir}/AdGuardHome.bak" "$agh_bin"
	start_service

	return 0
}

# Function confirm_running waits for the service to settle, and undoes the
# install if it does not.
#
# `systemctl start` returns as soon as the process is spawned, so a binary
# that aborts a second later looks exactly like one that worked -- and with
# `Restart=always` in front of it, the machine then has no DNS and a unit that
# says it is starting.  On the machine whose resolver this is, that difference
# is the whole network, so it is worth eight seconds to tell them apart.
confirm_running() {
	i='0'
	while [ "$i" -lt '8' ]; do
		sleep 1
		i=$((i + 1))

		if ! service_is_running; then
			echo "the service did not stay up" 1>&2

			case "$os" in
			'darwin') ;;
			*)
				# `1>&2` before `2>/dev/null`, or the journal -- which is
				# where the reason actually is -- goes to the same place the
				# errors were just sent.
				systemctl status AdGuardHome --no-pager 2>&1 | head -12 1>&2
				journalctl -u AdGuardHome -n 15 --no-pager 1>&2 2>/dev/null \
					|| true
				;;
			esac

			if rollback; then
				error_exit "put the previous binary back and started it
the one that failed is beside it as ${agh_dir}/AdGuardHome.failed, and
nothing else was changed"
			fi

			error_exit "there is no previous binary to go back to
$agh_bin is installed but not running"
		fi
	done

	log 'the service is still up after eight seconds'

	# Left by an earlier run that did not stay up.  This one did, so it is
	# nothing but a confusing ten megabytes.
	rm -f "${agh_dir}/AdGuardHome.failed"
}

# Function start_service starts the service.
start_service() {
	log 'starting the service'

	case "$os" in
	'darwin')
		launchctl load -w "$(service_unit_path)"
		;;
	*)
		systemctl start AdGuardHome
		;;
	esac
}

# Function resolve_tag sets tag to the newest release, unless one was named.
#
# The release carries a version.txt whose whole content is its own tag, so the
# common case is a single unauthenticated GET that no rate limit applies to.
# The API is the fallback, for a release published without that file.
resolve_tag() {
	if [ "$tag" != '' ]; then
		log "release: $tag (named on the command line)"

		return 0
	fi

	tag="$(
		"$download_func" "${base_url}/latest/download/version.txt" 2>/dev/null \
			| tr -d ' \t\r\n' \
			|| true
	)"

	case "$tag" in
	'v'[0-9]*)
		log "release: $tag"

		return 0
		;;
	esac

	log 'version.txt is not published for the latest release; asking the API'

	tag="$(
		"$download_func" "$api_url" 2>/dev/null \
			| sed -n 's/.*"tag_name"[ ]*:[ ]*"\([^"]*\)".*/\1/p' \
			| head -1 \
			|| true
	)"

	case "$tag" in
	'v'[0-9]*)
		log "release: $tag"
		;;
	*)
		error_exit "cannot work out the latest release from $base_url
name one with -t, for example -t v0.5.0"
		;;
	esac
}

# Function decide stops the script when there is nothing to do, and otherwise
# says what it is about to do.
decide() {
	case "$existing" in
	'none')
		action='install'
		;;
	'sift')
		if [ "$existing_version" = "$tag" ] && [ "$reinstall" -ne '1' ]; then
			echo "sift $tag is already installed in $agh_dir; nothing to do"
			echo 'pass -r to install it again anyway'

			exit 0
		fi

		action='upgrade'
		;;
	'adguardhome')
		action='replace'
		;;
	*)
		if [ "$reinstall" -ne '1' ]; then
			error_exit "$agh_bin is something this script does not recognise
it reported: ${reported:-nothing}
pass -r to replace it anyway"
		fi

		action='replace'
		;;
	esac

	readonly action

	case "$action" in
	'install')
		echo "installing sift $tag into $agh_dir"
		;;
	'upgrade')
		echo "upgrading sift $existing_version to $tag in $agh_dir"
		;;
	'replace')
		echo "replacing ${existing_version:-the binary} in $agh_dir with sift $tag"
		echo 'the config file, the data directory and the service stay as they are'
		;;
	esac
}

# Function do_uninstall removes the binary and the service, and keeps
# everything that holds a setting or a record.
do_uninstall() {
	if [ "$existing" = 'none' ]; then
		echo "nothing is installed in $agh_dir"

		exit 0
	fi

	stop_service

	if service_installed; then
		log 'removing the service'

		( cd "$agh_dir" && ./AdGuardHome -s uninstall ) || {
			log 'the binary could not remove its own service; removing the unit'

			rm -f "$(service_unit_path)"
			[ "$os" = 'darwin' ] || systemctl daemon-reload || true
		}
	fi

	rm -f "$agh_bin" "${agh_dir}/AdGuardHome.bak" "${agh_dir}/AdGuardHome.failed" \
		"${agh_dir}/LICENSE.txt" "${agh_dir}/README.md"

	printf '%s\n' \
		"removed the binary and the service from $agh_dir" \
		'the config file and the data directory were kept; remove them with:' \
		"	rm -r $agh_dir"

	exit 0
}

# Function fetch downloads the release archive and its checksums into the
# staging directory.
fetch() {
	pkg_name="sift_${os}_${cpu}.tar.gz"
	pkg_url="${base_url}/download/${tag}/${pkg_name}"
	readonly pkg_name pkg_url

	log "downloading $pkg_url"

	if ! "$download_func" "$pkg_url" "${stage}/${pkg_name}"; then
		error_exit "cannot download $pkg_url
this release may not carry a build for ${os}_${cpu}"
	fi

	if ! "$download_func" "${base_url}/download/${tag}/checksums.txt" \
		"${stage}/checksums.txt" 2>/dev/null; then
		log 'the release publishes no checksums.txt'

		return 0
	fi

	verify_checksum
}

# Function verify_checksum checks the downloaded archive against the published
# digest, when the machine has something to compute one with.
verify_checksum() {
	expected="$(
		sed -n "s/^\([0-9a-f]\{64\}\) [ *]*${pkg_name}\$/\1/p" \
			"${stage}/checksums.txt" | head -1
	)"

	if [ "$expected" = '' ]; then
		log "checksums.txt does not name $pkg_name"

		return 0
	fi

	if is_command 'sha256sum'; then
		actual="$(sha256sum "${stage}/${pkg_name}" | cut -d ' ' -f 1)"
	elif is_command 'shasum'; then
		actual="$(shasum -a 256 "${stage}/${pkg_name}" | cut -d ' ' -f 1)"
	elif is_command 'openssl'; then
		actual="$(openssl dgst -sha256 "${stage}/${pkg_name}" | sed 's/.*= *//')"
	else
		log 'no sha256 tool on this machine; the download is unverified'

		return 0
	fi

	if [ "$expected" != "$actual" ]; then
		error_exit "$pkg_name does not match its published checksum
expected $expected
got      $actual"
	fi

	log 'checksum verified'
}

# Function unpack extracts the archive into the staging directory and checks
# that what came out is what is about to be installed.
unpack() {
	log "unpacking $pkg_name"

	tar -C "$stage" -x -z -f "${stage}/${pkg_name}"

	if [ ! -f "${stage}/AdGuardHome/AdGuardHome" ]; then
		error_exit "$pkg_name does not contain AdGuardHome/AdGuardHome"
	fi

	chmod 0755 "${stage}/AdGuardHome/AdGuardHome"

	reported_new="$("${stage}/AdGuardHome/AdGuardHome" --version 2>/dev/null || true)"
	case "$reported_new" in
	'Sift, version '*)
		log "downloaded $reported_new"
		;;
	*)
		# A binary for another cpu or another libc fails here rather than
		# after it has replaced a working server.
		error_exit "the downloaded binary does not run on this machine
it reported: ${reported_new:-nothing}"
		;;
	esac

	new_version="$(
		printf '%s\n' "$reported_new" \
			| sed -n 's/^[^,]*, version \([^ ][^ ]*\).*/\1/p' \
			| head -1
	)"

	# What gets installed is the binary, not the tag it was filed under, and
	# the next run compares the binary.  A release whose archive holds another
	# version would otherwise be installed again on every run, for ever.
	if [ "$new_version" != "$tag" ]; then
		echo "warning: the archive published under $tag holds ${new_version:-no version}" 1>&2
		echo 'warning: this installation will look out of date until they agree' 1>&2
	fi
}

# Function install_files puts the new binary in place, keeping the old one
# next to it under .bak so that going back is a stop, a mv and a start.
install_files() {
	mkdir -p "$agh_dir"

	stop_service

	if [ -e "$agh_bin" ]; then
		log "keeping the previous binary as ${agh_dir}/AdGuardHome.bak"

		mv -f "$agh_bin" "${agh_dir}/AdGuardHome.bak"
	fi

	mv -f "${stage}/AdGuardHome/AdGuardHome" "$agh_bin"
	chmod 0755 "$agh_bin"

	# tar restores the ids the archive carries, which are whoever built it.
	chown 0:0 "$agh_bin" 2>/dev/null || true

	for f in LICENSE.txt README.md; do
		if [ -f "${stage}/AdGuardHome/${f}" ]; then
			mv -f "${stage}/AdGuardHome/${f}" "${agh_dir}/${f}"
			chown 0:0 "${agh_dir}/${f}" 2>/dev/null || true
		fi
	done
}

# Function ensure_service installs the service if the machine has none, and
# starts it either way.
#
# An existing unit is never rewritten.  It is the operator's file -- it may
# name a different config, drop privileges, or order itself after something on
# the machine -- and both builds take the same arguments, so there is nothing
# in it that needs to change.
ensure_service() {
	if service_installed; then
		log 'keeping the installed service definition'
	else
		log 'installing the service'

		if ! ( cd "$agh_dir" && ./AdGuardHome -s install ); then
			error_exit "cannot install sift as a service
the binary is in place; run it by hand with: $agh_bin"
		fi
	fi

	start_service
}

# Function report says what happened and how to drive it.
report() {
	web_addr=''
	if [ -r "${agh_dir}/AdGuardHome.yaml" ]; then
		# The address under the top-level http: key, and no other.
		web_addr="$(
			awk '/^http:/ { in_http = 1; next }
			     /^[^ \t]/ { in_http = 0 }
			     in_http && $1 == "address:" { print $2; exit }' \
				"${agh_dir}/AdGuardHome.yaml"
		)"
	fi

	echo ''
	case "$action" in
	'install')
		echo "sift $new_version is installed and running"
		;;
	*)
		echo "sift $new_version is running; the config file and the data directory were untouched"
		;;
	esac

	if [ "$web_addr" != '' ]; then
		echo "the web interface is on ${web_addr}"
	fi

	if [ "$existing" = 'adguardhome' ]; then
		printf '%s\n' \
			'' \
			'AdGuard Home was kept as AdGuardHome.bak.  To go back to it:' \
			"	$sudo_cmd systemctl stop AdGuardHome" \
			"	$sudo_cmd mv ${agh_dir}/AdGuardHome.bak $agh_bin" \
			"	$sudo_cmd systemctl start AdGuardHome"
	fi

	printf '%s\n' \
		'' \
		'control the service with:' \
		"	$sudo_cmd $agh_bin -s start|stop|restart|status|install|uninstall"
}

# Entrypoint

# Set default values of configuration variables.
reinstall='0'
uninstall='0'
verbose='0'
cpu=''
os=''
out_dir=''
tag=''
base_url='https://github.com/openhoangnc/sift/releases'
api_url='https://api.github.com/repos/openhoangnc/sift/releases/latest'
script_url='https://raw.githubusercontent.com/openhoangnc/sift/main/scripts/install.sh'
download_func='download_curl'
sudo_cmd='sudo'
stage=''
new_version=''

parse_opts "$@"

echo 'starting the sift installation script'

set_os
set_cpu
set_download_func
check_required

if ! is_root; then
	rerun_with_root
fi

locate_install
inspect_existing

if [ "$uninstall" -eq '1' ]; then
	do_uninstall
fi

resolve_tag
decide

# Staged beside the target rather than in /tmp, so that moving the binary into
# place is a rename within one filesystem and not a copy that can be
# interrupted half-written.
stage="${agh_dir}.install.$$"
readonly stage

trap 'rm -r -f "$stage"' EXIT INT TERM
mkdir -p "$stage"

fetch
unpack
install_files
ensure_service
confirm_running
report
