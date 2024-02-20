package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"bufio"
	// "slices"
	"golang.org/x/exp/slices"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

// dynamically link with -ldflags "-X main.hiddenFlag=flag{example_flag}
var hiddenFlag string

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
				// fmt.Printf("User without a password found: %s\n", fields[0])
				return false
			}
			return true
		}
	}

	return false
	// To pass: passwd dave
}

func level7() bool {
	cmd := exec.Command("ss", "-tuln")

	out, err := cmd.Output()
	check(err)

	output := string(out)

	// Check if port 3306 is not in the listening state
	if !strings.Contains(output, ":3306") {
		fmt.Println("Level Solved: No listener found on port 3306.")
		return true
	} else {
		return false
	}
	// To pass: kill the process listening on port 3306
}

func level8() bool {
	// e.g. firewall allow only ssh connections
	cmd := exec.Command("sudo", "ufw", "status", "verbose")
	out, err := cmd.Output()
	check(err)

	output := string(out)

	if !strings.Contains(output, "Default: deny (incoming)") || !strings.Contains(output, "22/tcp") {
		// fmt.Println("Firewall not properly configured for SSH only or default deny incoming.")
		return false
	}

	// fmt.Println("Level solved: Firewall configured correctly.")
	return true
	// sudo ufw default deny incoming
	// sudo ufw allow ssh
	// sudo ufw enable
}

func levelBonus() bool {
	// Check if the hiddenFlag has already been found
	if hiddenFlag == "" {
		fmt.Println("You already found the flag! :)")
		return true
	}
	fmt.Print("Enter the flag (Format: flag{...}): ")
	scanner := bufio.NewScanner(os.Stdin)
	if scanner.Scan() {
		userInput := scanner.Text()
		if userInput == hiddenFlag {
			fmt.Println("Correct flag! :D")
			// Empty flag for check
			hiddenFlag = ""
			return true
		} else {
			fmt.Println("Incorrect flag. :( Try again.")
			return false
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
		return false
	}

	// Should not reach here
	return false
}
  
func printhint(level string) {
	switch level {
	case "level 1":
		fmt.Println("- Try checking if your sshd config is living up to current best practices regarding password-based logins")
	case "level 1.5":
		fmt.Println("- How are users supposed to login via SSH without password authentication?")
	case "level 1.75":
		fmt.Println("- It's not always a good idea to let users log in as root")
	case "level 2":
		fmt.Println("- Ensure your iptables configuration protects against brute-force attempts.")
	case "level 3":
		fmt.Println("- What are SUID binaries and how can you list all of them on your system? Which ones can be used by attackers to perform priviledge escalation")
	case "level 4":
		fmt.Println("- Try finding out if any users can run commands as sudo. Should the user be able to run that command? Could it be dangerous?")
	case "level 5":
		fmt.Println("- Check for unexpected user entries in /etc/passwd that could indicate security issues.")
	case "level 6":
		fmt.Println("- Check for non-service users without a password set and remove them")
	case "level 7":
		fmt.Println("- Make sure you then expose ports on the server needlessly")
	case "level 8":
		fmt.Println("- Check firewall rules. No incoming traffic except ssh should be allowed...")
	case "level (bonus)":
		fmt.Println("- There is a hidden flag somewhere... Format of the flag: flag{...} ")
	}
}

func printLevelResult(level string, passed bool) {
	if passed {
		fmt.Printf("%s:\t☒\n", level)
	} else {
		fmt.Printf("%s:\t☐\n", level)
		if hintFlag {
			printhint(level)
		}
	}
}

var hintFlag bool

func main() {

	flag.BoolVar(&hintFlag, "hints", false, "Shows hint for each level. Try to not use this too much")
	flag.Parse()

	levelResults := make(map[string](bool))
	// Retain order of the output
	levelOrdered := []string{"level 1", "level 1.5", "level 1.75", "level 2", "level 3", "level 4", "level 5", "level 6", "level 7", "level 8", "level (bonus)"}
	bonusLevel := "level (bonus)"

	levelResults["level 1"] = level1("PasswordAuthentication", "no")
	levelResults["level 1.5"] = level1("PubkeyAuthentication", "yes")
	levelResults["level 1.75"] = level1("PermitRootLogin", "no")
	levelResults["level 2"] = level2()
	levelResults["level 3"] = level3()
	levelResults["level 4"] = level4()
	levelResults["level 5"] = level5()
	levelResults["level 6"] = level6()
	levelResults["level 7"] = level7()
	levelResults["level 8"] = level8()
	levelResults[bonusLevel] = false

	allLevelsPassed := true
	for _, level := range levelOrdered {
		passed, exists := levelResults[level]
		if !exists || !passed {
			allLevelsPassed = false
			break
		}
	}

	if allLevelsPassed {
		// Only check the bonus level if all other levels have been passed.
		levelResults[bonusLevel] = levelBonus()
	}

	for _, level := range levelOrdered {
		printLevelResult(level, levelResults[level])
	}

	if allLevelsPassed {
		printLevelResult(bonusLevel, levelResults[bonusLevel])
	}
}

// Do some iptable stuff regarding our nice ssh server, such as rate limiting. Check for whatever method is taught by the course
// DO some fail2ban stuff
// Do some SUID stuff - check
// Do some sudo -l with insecure path stuff
// Do some users with empty passwords stuff?
// Read more about linux server hardening
// maybe some selinux stuff
// maybe some firewall stuff? firewalld or ufw
// https://www.pluralsight.com/blog/it-ops/linux-hardening-secure-server-checklist stuff about password reuse is cool, also forcing users to change passwords
// 11. Locking User Accounts After Login Failures
// Make Sure No Non-Root Accounts Have UID Set To 0
// Only allow root to access CRON
//  /etc/shadow
// 3. Set strong password policy
// IDEA: set an interactive shell for a service account in passwd
// IDEA: bonus levels with linux backdoors??? Could be cool.
// IDEA: Add the option to disallow users to reuse old passwords
