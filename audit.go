package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func level1(option string, value string) bool {
	// Check if ssh allows login via password
	dat, err := os.ReadFile("/etc/ssh/sshd_config")
	check(err)

	stringArr := strings.Split(string(dat), "\n")

	// Go through the config, find all active lines with PasswordAuthentication
	// Only the last line for the option in the config counts
	optionArr := []string{}

	for _, s := range stringArr {
		// Trim leading and trailing whitespace from the line
		trimmedLine := strings.TrimSpace(s)
		// fmt.Println(trimmedLine)

		// Skip empty lines and commented-out lines
		if trimmedLine == "" || strings.HasPrefix(trimmedLine, "#") {
			continue
		}

		fields := strings.Fields(trimmedLine)
		// Check if the first field matches the option we're looking for
		if len(fields) > 1 && fields[0] == option {
			// Add the option value to the slice
			optionArr = append(optionArr, fields[1])
		}
	}

	fmt.Println(optionArr)

	// Check if the last occurrence of the option has the desired value
	if len(optionArr) > 0 {
		return strings.ToLower(optionArr[len(optionArr)-1]) == strings.ToLower(value)
	}
	// If option not found return false
	return false
}

func level2() bool {
	// Execute the iptables command to list all rules
	cmd := exec.Command("sudo", "iptables", "-S")
	out, err := cmd.Output()
	if err != nil {
		fmt.Println("Error executing iptables command:", err)
		return false
	}

	// Convert the output to a string for parsing
	output := string(out)

	// Define required parts for a rate limiting rule on port 22
	requiredParts := []string{
		"-p tcp",
		"--dport 22",
		"-m limit",
		"--limit",
	}

	// Check if the output contains all of the required parts. If so then it is probably correct(?)
	containsAllParts := true
	for _, part := range requiredParts {
		if !strings.Contains(output, part) {
			containsAllParts = false
			break
		}
	}

	return containsAllParts // Returns true if all parts are found, false otherwise
	// Example command to pass: sudo iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m limit --limit 3/min -j ACCEPT
}

func level3() bool {
	// Check if dangerous suid binaries exist on system (python3, find, vim)
	cmd := exec.Command("/bin/find", "/", "-perm", "-4000")
	cmd.Stderr = nil // ignore errors

	out, _ := cmd.Output()
	// check(err)

	bins := strings.Fields(string(out))

	return !(slices.Contains(bins, "/usr/bin/vim") || slices.Contains(bins, "/usr/bin/find") || slices.Contains(bins, "/usr/bin/python3"))
	// To pass: sudo chmod u-s /usr/bin/find
}

func level4() bool {
	// Check if dangerous sudo permissions are given for user bitty
	cmd := exec.Command("/bin/cat", "/etc/sudoers.d/bitty")
	out, _ := cmd.Output()

	if strings.Contains(string(out), "/bin/less /root/log_file.txt") {
		return false
	}

	return true
	// To pass: rm rf /etc/sudoers.d/bitty
}

func level5() bool {
	// Read the /etc/passwd file to find UIDs
	dat, err := os.ReadFile("/etc/passwd")
	check(err)

	passwdLines := strings.Split(string(dat), "\n")
	for _, line := range passwdLines {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		// Ensure line has enough fields and UID field exists
		if len(fields) > 2 {
			uid := fields[2]
			username := fields[0]

			// Check for UID 0 that is not the root user
			if uid == "0" && username != "root" {
				return false
			}
		}
	}
	return true // No security issues found
	// TO pass, either use usermod -u 1111 dave, or manually edit passwd file

}

func level6() bool {
	// Read the /etc/shadow file to check for the dave user's password
	dat, err := os.ReadFile("/etc/shadow")
	check(err)

	shadowLines := strings.Split(string(dat), "\n")
	for _, line := range shadowLines {
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		if fields[0] == "dave" {
			// Check if the password field is empty, "*", or "!"
			passwordField := fields[1]
			if passwordField == "" || passwordField == "*" || passwordField == "!" {
				fmt.Printf("User without a password found: %s\n", fields[0])
				return false
			}
			return true
		}
	}

	return false // If dave is not found in /etc/shadow, consider it a fail
	// To pass: passwd dave
}

func level7() bool {
	// Read the /etc/shadow file
	dat, err := os.ReadFile("/etc/shadow")
	check(err)

	shadowLines := strings.Split(string(dat), "\n")
	for _, line := range shadowLines {
		// Skip empty lines
		if line == "" {
			continue
		}
		fields := strings.Split(line, ":")
		// Ensure line has enough fields for password age checks
		if len(fields) < 5 {
			continue
		}
		lastPasswordChangeDay := fields[2]
		maxPasswordAgeDays := fields[4]

		// Convert last password change day to integer
		lastChange, err := strconv.Atoi(lastPasswordChangeDay)
		if err != nil {
			continue // Skip if conversion fails
		}

		// Convert max password age days to integer
		maxAge, err := strconv.Atoi(maxPasswordAgeDays)
		if err != nil || maxAge == 0 {
			continue // Skip if conversion fails or maxAge is not set
		}

		// Calculate the age of the password
		lastChangeDate := time.Unix(int64(lastChange*86400), 0)
		ageDays := time.Since(lastChangeDate).Hours() / 24

		if float64(maxAge) < ageDays || ageDays > 90 {
			fmt.Printf("User with password age issue found: %s\n", fields[0])
			return false // Password age exceeds 90 days or maxAge
		}
	}

	return true // All user passwords comply with the age policy
}

var hintFlag bool

func main() {
	// Maybe define a custom flag and hide a flag in it for the reversers???

	flag.BoolVar(&hintFlag, "hints", false, "Shows hint for each level. Try to not use this too much")
	flag.Parse()

	if !level1("PasswordAuthentication", "no") {
		fmt.Println("1: ☐")
		if hintFlag {
			fmt.Println("- Try checking if your sshd config is living up to current best practices regarding password-based logins")
		}
		os.Exit(0)
	}
	fmt.Println("1: ☒")
	// Maybe add a short explainer after each level with what they did right
	if !level1("PubkeyAuthentication", "yes") {
		fmt.Println("1.5: ☐")
		if hintFlag {
			fmt.Println("- How are users supposed to login via SSH without password authentication?")
		}
		os.Exit(0)
	}
	fmt.Println("1.5: ☒")

	if !level2() {
		fmt.Println("2: ☐")
		if hintFlag {
			fmt.Println("- Ensure your iptables configuration protects against brute-force SSH login attempts.")
		}
		os.Exit(0)
	}
	fmt.Println("2: ☒")

	if !level3() {
		fmt.Println("3: ☐")
		if hintFlag {
			fmt.Println("- What are SUID binaries and how can you list all of them on your system? Which ones can be used by attackers to perform priviledge escalation")
		}
		os.Exit(0)
	}
	fmt.Println("3: ☒")

	if !level4() {
		fmt.Println("4: ☐")
		if hintFlag {
			fmt.Println("- Try finding out if any users can run commands as sudo. Should the user be able to run that command? Could it be dangerous?")
		}
		os.Exit(0)
	}
	fmt.Println("4: ☒")

	if !level5() {
		fmt.Println("5: ☐")
		if hintFlag {
			fmt.Println("- Check for unexpected user entries in /etc/passwd that could indicate security issues.")
		}
		os.Exit(0)
	}
	fmt.Println("5: ☒")

	if !level6() {
		fmt.Println("6: ☐")
		if hintFlag {
			fmt.Println("- Check for non-service users without a password set and remove them")
		}
		os.Exit(0)
	}
	fmt.Println("6: ☒")

	if !level7() {
		fmt.Println("7: ☐")
		if hintFlag {
			fmt.Println("- Ensure all user passwords are changed at least every 90 days.") // maybe remove this chall we've kinda talked shit about this during lectures
		}
		os.Exit(0)
	}
	fmt.Println("7: ☒")

	// Do some iptable stuff regarding our nice ssh server, such as rate limiting. Check for whatever method is taught by the course
	// DO some fail2ban stuff
	// Do some SUID stuff - check
	// Do some sudo -l with insecure path stuff
	// Do some users with empty passwords stuff?
	// Read more about linux server hardening
	//maybe some selinux stuff
	// maybe some firewall stuff? firewalld or ufw
	// https://www.pluralsight.com/blog/it-ops/linux-hardening-secure-server-checklist stuff about password reuse is cool, also forcing users to change passwords
	// 11. Locking User Accounts After Login Failures
	// Make Sure No Non-Root Accounts Have UID Set To 0
	// Only allow root to access CRON
	//  /etc/shadow
	// 3. Set strong password policy
	// IDEA: set an interactive shell for a service account in passwd
	// IDEA: bonus levels with linux backdoors??? Could be cool.
}
