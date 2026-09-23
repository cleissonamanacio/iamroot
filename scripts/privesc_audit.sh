

emit() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6"
}

[ "$1" = "--quiet" ] || echo "[*] iamroot structured audit (shell supplement)" >&2

for d in /bin /usr/bin /sbin /usr/sbin /usr/local/bin; do
    [ -d "$d" ] || continue
    while IFS= read -r f; do
        base=$(basename "$f")
        case "$base" in
            pkexec) emit CRITICAL suid "SUID pkexec" "$f" "patch polkit (USN-5252-1)" 30 ;;
            find|bash|cp|vim|nmap|python|python3|php|env|perl|ruby|less|tar|chmod|dd|tee)
                emit CRITICAL suid "Dangerous SUID binary" "$f" "remove SUID bit or restrict" 30 ;;
        esac
    done < <(find "$d" -maxdepth 1 -perm -4000 -type f 2>/dev/null)
done

if [ -w /etc/passwd ]; then
    emit CRITICAL files "/etc/passwd writable" "UID-0 injection possible" \
        "chmod 644 /etc/passwd" 35
fi
if [ -r /etc/shadow ] && [ "$(id -u)" != 0 ]; then
    emit CRITICAL files "/etc/shadow readable" "hash extractable" "chmod 640 /root 600" 30
fi

if command -v sudo >/dev/null 2>&1; then
    sudo -V 2>/dev/null | head -1 | grep -qE '1\.8\.|1\.9\.0|1\.9\.5' \
        && emit WARNING sudo "sudo in Baron Samedit range" "$(sudo -V|head -1)" "upgrade sudo" 20
    sudo -n -l 2>/dev/null | grep -q NOPASSWD \
        && emit CRITICAL sudo "NOPASSWD sudo rule" "$(sudo -n -l|grep NOPASSWD)" "restrict sudoers" 30
fi

if command -v getcap >/dev/null 2>&1; then
    getcap -r / 2>/dev/null | grep -qiE 'cap_setuid|cap_dac_override|cap_sys_admin' \
        && emit CRITICAL caps "Dangerous capability" "$(getcap -r / 2>/dev/null|grep -iE 'cap_setuid|cap_dac')" "drop caps" 25
fi

id -nG 2>/dev/null | tr ' ' '\n' | grep -qx docker \
    && emit CRITICAL group "docker group" "host root via socket" "remove from docker group" 35
id -nG 2>/dev/null | tr ' ' '\n' | grep -qxE 'lxd|lxc' \
    && emit CRITICAL group "lxd group" "privileged container escape" "remove from lxd group" 35

[ -f /.dockerenv ] && emit WARNING env "Docker container" "escape required" "harden container" 20
emit INFO kernel "kernel release" "$(uname -r)" "n/a" 0
