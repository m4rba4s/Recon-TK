
package logger

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/sirupsen/logrus"
)

type CynicalLevel int

const (
	LevelChill CynicalLevel = iota
	LevelSarcastic
	LevelBrutal
	LevelSavage
)

type CynicalLogger struct {
	*logrus.Logger
	level         CynicalLevel
	target        string
	sessionID     string
	findings      int
	vulnsFound    int
	bypassCount   int
	startTime     time.Time
	encrypted     bool
	obfuscated    bool
}

var (
	startMessages = map[CynicalLevel][]string{
		LevelChill: {
			"🎯 Starting the bug hunt, colleague",
			"🔍 Time to show what we can do",
			"⚡ Launching scan, hope admin isn't sleeping",
			"🎯 Начинаем охоту на багов, коллега",
			"🔍 Время показать что умеем",
			"⚡ Запускаем сканирование, надеюсь админ не спит",
		},
		LevelSarcastic: {
			"🎭 Well, let's look at this 'secured' server",
			"🤡 Admin probably thinks their WAF is cool",
			"🎪 Time to put on a circus for the security team",
			"🎭 Ну что, посмотрим на этот 'защищенный' сервер",
			"🤡 Админ наверное думает что его WAF крутой",
			"🎪 Время устроить цирк для системы безопасности",
		},
		LevelBrutal: {
			"💀 Get ready to get fucked, server",
			"⚰️ Now we'll show who's daddy here",
			"🔥 Time to burn everything to hell",
			"💀 Готовься получать пизды, сервер",
			"⚰️ Сейчас покажем кто тут папа",
			"🔥 Время сжечь все к хуям",
		},
		LevelSavage: {
			"🖕 Lamer admin, get ready to cry",
			"💣 Blowing this shithole to hell",
			"⚡ Getting root on this garbage",
			"🖕 Ламер-админ, готовься плакать",
			"💣 Взрываем эту поебень нахер",
			"⚡ Делаем рут на этом говне",
		},
	}

	vulnFoundMessages = map[CynicalLevel][]string{
		LevelChill: {
			"🎯 Vulnerability found: %s",
			"📍 Entry point discovered: %s",
			"✨ Interesting finding: %s",
			"🎯 Найдена уязвимость: %s",
			"📍 Обнаружена точка входа: %s",
			"✨ Интересная находка: %s",
		},
		LevelSarcastic: {
			"🤦‍♂️ Seriously? %s - that's a classic",
			"🎭 Admin forgot about %s, how cute",
			"🤡 %s - even a schoolkid would fix this",
			"🤦‍♂️ Серьезно? %s - это же классика",
			"🎭 Админ забыл про %s, как мило",
			"🤡 %s - даже школьник это исправил бы",
		},
		LevelBrutal: {
			"💀 Lamer, %s is full of holes like a sieve",
			"⚰️ %s - this is some fucked up shit",
			"🔥 %s burns with blue flame",
			"💀 Ламер, %s дырявая как решето",
			"⚰️ %s - это пиздец какой-то",
			"🔥 %s горит синим пламенем",
		},
		LevelSavage: {
			"🖕 %s - shitty admin sucks dicks",
			"💣 %s exploded like Chernobyl",
			"⚡ %s leaks like an old pussy",
			"🖕 %s - хуевый админ сосет хуи",
			"💣 %s взорвалась как чернобыль",
			"⚡ %s течет как старая пизда",
		},
	}

	bypassMessages = map[CynicalLevel][]string{
		LevelChill: {
			"🥷 WAF bypassed successfully",
			"🎯 Protection overcome",
			"✨ Barrier broken",
			"🥷 WAF обойден успешно",
			"🎯 Защита преодолена",
			"✨ Барьер сломан",
		},
		LevelSarcastic: {
			"🤡 WAF thought it was cool, haha",
			"🎭 'Protection' like a leaky condom",
			"🤦‍♂️ This firewall stands like a dick in the cold",
			"🤡 WAF думал что крутой, ха-ха",
			"🎭 'Защита' как дырявый презерватив",
			"🤦‍♂️ Этот файрвол стоит как хуй на морозе",
		},
		LevelBrutal: {
			"💀 WAF sucks like a vacuum cleaner",
			"⚰️ Protection weaker than a virgin's",
			"🔥 Firewall burns in hell",
			"💀 WAF сосет как пылесос",
			"⚰️ Защита слабее чем у девственницы",
			"🔥 Файрвол горит в аду",
		},
		LevelSavage: {
			"🖕 WAF sucks dicks to hell",
			"💣 Protection like a whore's - none",
			"⚡ Admin is a moron, WAF is shit",
			"🖕 WAF сосет хуи нахер",
			"💣 Защита как у блядины - никакой",
			"⚡ Админ долбоеб, WAF говно",
		},
	}

	exploitMessages = map[CynicalLevel][]string{
		LevelChill: {
			"🎯 Exploit works: %s",
			"💡 Successful exploitation: %s",
			"🔓 Access gained through: %s",
			"🎯 Эксплойт работает: %s",
			"💡 Успешная эксплуатация: %s",
			"🔓 Доступ получен через: %s",
		},
		LevelSarcastic: {
			"🤡 %s works like Swiss clockwork",
			"🎭 %s - admin definitely didn't know about this",
			"🤦‍♂️ %s - this is already memes on the internet",
			"🤡 %s работает как часы швейцарские",
			"🎭 %s - админ точно не знал об этом",
			"🤦‍♂️ %s - это уже мемы в интернете",
		},
		LevelBrutal: {
			"💀 %s fucked the system to pieces",
			"⚰️ %s - admin is now unemployed",
			"🔥 %s burned everything to hell",
			"💀 %s разъебал систему в хлам",
			"⚰️ %s - админ теперь безработный",
			"🔥 %s сжег все к ебеням",
		},
		LevelSavage: {
			"🖕 %s - lamer admin cries like a bitch",
			"💣 %s blew up servers to hell",
			"⚡ %s - admin goes to hell to quit",
			"🖕 %s - ламер-админ плачет как сука",
			"💣 %s взорвал серваки нахер",
			"⚡ %s - админ идет нахуй увольняться",
		},
	}

	completionMessages = map[CynicalLevel][]string{
		LevelChill: {
			"✅ Scanning completed successfully",
			"🎯 All tasks completed",
			"📊 Report ready for review",
			"✅ Сканирование завершено успешно",
			"🎯 Все задачи выполнены",
			"📊 Отчет готов к просмотру",
		},
		LevelSarcastic: {
			"🎭 Work done, admin can go cry",
			"🤡 All holes found, now patch them",
			"🤦‍♂️ Server checked, result is sad",
			"🎭 Работа выполнена, админ может идти плакать",
			"🤡 Все дыры найдены, теперь их латать",
			"🤦‍♂️ Сервер проверен, результат печальный",
		},
		LevelBrutal: {
			"💀 Server fucked, admin is depressed",
			"⚰️ System destroyed morally",
			"🔥 Everything burned, admin at job center",
			"💀 Сервер разъебан, админ в депрессии",
			"⚰️ Система уничтожена морально",
			"🔥 Все сгорело, админ на бирже труда",
		},
		LevelSavage: {
			"🖕 Lamers pissed on, job done",
			"💣 Servers blown up, admins suck",
			"⚡ Everything fucked to hell, moving on",
			"🖕 Ламеры обоссаны, работа сделана",
			"💣 Серваки взорваны, админы сосут",
			"⚡ Все нахер разнесено, идем дальше",
		},
	}

	stealthMessages = []string{
		"🥷 Активирован невидимый режим",
		"👻 Становимся призраками в сети",
		"🌫️ Растворяемся в трафике",
		"🔮 Магия обфускации активна",
		"🎭 Надеваем маску анонимности",
	}

	obfuscationMessages = []string{
		"🔀 Пейлоады замаскированы",
		"🎲 Рандомизация активна",
		"🌀 Запутываем следы",
		"🔧 Мутируем запросы",
		"🎨 Обфусцируем трафик",
	}

	encryptionMessages = []string{
		"🔐 Все зашифровано нахер",
		"🛡️ Траффик закрыт от глаз",
		"🔒 NSA нервно курит",
		"🛡️ Шифруем все что можно",
		"🔐 Даже боги не расшифруют",
	}
)

func NewCynicalLogger(target string, level CynicalLevel) *CynicalLogger {
	logger := logrus.New()
	
	logger.SetFormatter(&CynicalFormatter{})
	
	logsDir := "logs"
	os.MkdirAll(logsDir, 0755)
	
	timestamp := time.Now().Format("20060102_150405")
	logFile := filepath.Join(logsDir, fmt.Sprintf("elite_session_%s.log", timestamp))
	
	file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		logger.SetOutput(file)
	}

	sessionID := generateSessionID()
	
	cynicalLogger := &CynicalLogger{
		Logger:     logger,
		level:      level,
		target:     target,
		sessionID:  sessionID,
		startTime:  time.Now(),
		encrypted:  true,
		obfuscated: true,
	}
	
	cynicalLogger.LogStart()
	
	return cynicalLogger
}

type CynicalFormatter struct{}

func (f *CynicalFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := entry.Time.Format("15:04:05")
	level := strings.ToUpper(entry.Level.String())
	
	var colorFunc func(...interface{}) string
	switch entry.Level {
	case logrus.ErrorLevel:
		colorFunc = color.New(color.FgRed, color.Bold).SprintFunc()
	case logrus.WarnLevel:
		colorFunc = color.New(color.FgYellow, color.Bold).SprintFunc()
	case logrus.InfoLevel:
		colorFunc = color.New(color.FgCyan, color.Bold).SprintFunc()
	default:
		colorFunc = color.New(color.FgWhite).SprintFunc()
	}
	
	formatted := fmt.Sprintf("[%s] %s %s\n", 
		timestamp, 
		colorFunc(level), 
		entry.Message)
	
	return []byte(formatted), nil
}


func (cl *CynicalLogger) LogStart() {
	messages := startMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	color.Cyan("\n🚀 ELITE CYNICAL MODE ACTIVATED")
	color.Yellow("Target: %s", cl.target)
	color.Yellow("Session: %s", cl.sessionID)
	color.Green("Mode: %s", cl.getLevelName())
	
	if cl.encrypted {
		encMsg := encryptionMessages[randomInt(len(encryptionMessages))]
		color.Magenta(encMsg)
	}
	
	if cl.obfuscated {
		obfMsg := obfuscationMessages[randomInt(len(obfuscationMessages))]
		color.Blue(obfMsg)
	}
	
	stealthMsg := stealthMessages[randomInt(len(stealthMessages))]
	color.Green(stealthMsg)
	
	color.Cyan(message)
	cl.Info(fmt.Sprintf("Session started: %s | Target: %s", cl.sessionID, cl.target))
}

func (cl *CynicalLogger) LogVulnFound(vulnType, description string) {
	cl.vulnsFound++
	cl.findings++
	
	messages := vulnFoundMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	fullMessage := fmt.Sprintf(message, vulnType)
	
	switch {
	case strings.Contains(strings.ToLower(vulnType), "critical") || 
		 strings.Contains(strings.ToLower(vulnType), "rce") ||
		 strings.Contains(strings.ToLower(vulnType), "sqli"):
		color.Red("🔥 " + fullMessage)
		color.Red("   Details: %s", description)
		
	case strings.Contains(strings.ToLower(vulnType), "high") ||
		 strings.Contains(strings.ToLower(vulnType), "xss"):
		color.Yellow("⚡ " + fullMessage)
		color.Yellow("   Details: %s", description)
		
	default:
		color.Green("✨ " + fullMessage)
		color.Green("   Details: %s", description)
	}
	
	cl.Info(fmt.Sprintf("Vulnerability found: %s - %s", vulnType, description))
	
	cl.suggestCVE(vulnType)
}

func (cl *CynicalLogger) LogBypassSuccess(technique, details string) {
	cl.bypassCount++
	cl.findings++
	
	messages := bypassMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	color.Green("🥷 " + message)
	color.Green("   Technique: %s", technique)
	color.Green("   Details: %s", details)
	
	cl.Info(fmt.Sprintf("Bypass successful: %s - %s", technique, details))
}

func (cl *CynicalLogger) LogExploitSuccess(exploitType, target string) {
	cl.findings++
	
	messages := exploitMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	fullMessage := fmt.Sprintf(message, exploitType)
	
	color.Red("💀 " + fullMessage)
	color.Red("   Target: %s", target)
	
	cl.Info(fmt.Sprintf("Exploit successful: %s on %s", exploitType, target))
}

func (cl *CynicalLogger) LogStealth(action string) {
	stealthMsg := stealthMessages[randomInt(len(stealthMessages))]
	color.Magenta("🥷 " + stealthMsg + " (" + action + ")")
	cl.Debug(fmt.Sprintf("Stealth action: %s", action))
}

func (cl *CynicalLogger) LogObfuscation(technique string) {
	obfMsg := obfuscationMessages[randomInt(len(obfuscationMessages))]
	color.Blue("🔀 " + obfMsg + " (" + technique + ")")
	cl.Debug(fmt.Sprintf("Obfuscation: %s", technique))
}

func (cl *CynicalLogger) LogEncryption(method string) {
	encMsg := encryptionMessages[randomInt(len(encryptionMessages))]
	color.Cyan("🔐 " + encMsg + " (" + method + ")")
	cl.Debug(fmt.Sprintf("Encryption: %s", method))
}

func (cl *CynicalLogger) LogCompletion() {
	duration := time.Since(cl.startTime)
	
	messages := completionMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	color.Cyan("\n🎯 SESSION COMPLETE")
	color.Cyan("=" + strings.Repeat("=", 40))
	color.Green(message)
	color.White("Duration: %v", duration)
	color.White("Vulnerabilities: %d", cl.vulnsFound)
	color.White("Bypasses: %d", cl.bypassCount)
	color.White("Total Findings: %d", cl.findings)
	color.White("Session ID: %s", cl.sessionID)
	
	// Final cynical comment
	cl.addFinalComment()
	
	cl.Info(fmt.Sprintf("Session completed: Duration=%v, Vulns=%d, Bypasses=%d", 
		duration, cl.vulnsFound, cl.bypassCount))
}

func (cl *CynicalLogger) LogError(err error, context string) {
	errorMessages := map[CynicalLevel][]string{
		LevelChill: {
			"❌ Произошла ошибка: %s",
			"⚠️ Что-то пошло не так: %s",
		},
		LevelSarcastic: {
			"🤦‍♂️ Блять, опять ошибка: %s",
			"🤡 Система решила поебаться: %s",
		},
		LevelBrutal: {
			"💀 Все пошло по пизде: %s",
			"⚰️ Хуевая ошибка: %s",
		},
		LevelSavage: {
			"🖕 Ебаная ошибка нахер: %s",
			"💣 Все в жопе, ошибка: %s",
		},
	}
	
	messages := errorMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	color.Red(fmt.Sprintf(message, err.Error()))
	if context != "" {
		color.Yellow("Context: %s", context)
	}
	
	cl.Error(fmt.Sprintf("Error in %s: %v", context, err))
}

func (cl *CynicalLogger) LogWarning(warning, context string) {
	warningMessages := map[CynicalLevel][]string{
		LevelChill: {
			"⚠️ Внимание: %s",
			"🔔 Предупреждение: %s",
		},
		LevelSarcastic: {
			"🤦‍♂️ Опа, проблемка: %s",
			"🎭 Админ где-то налажал: %s",
		},
		LevelBrutal: {
			"💀 Хуевая ситуация: %s",
			"⚰️ Админ долбоеб: %s",
		},
		LevelSavage: {
			"🖕 Ебаная хуйня: %s",
			"💣 Пиздец какой-то: %s",
		},
	}
	
	messages := warningMessages[cl.level]
	message := messages[randomInt(len(messages))]
	
	color.Yellow(fmt.Sprintf(message, warning))
	cl.Warn(fmt.Sprintf("Warning in %s: %s", context, warning))
}


func (cl *CynicalLogger) getLevelName() string {
	names := map[CynicalLevel]string{
		LevelChill:     "Chill Mode",
		LevelSarcastic: "Sarcastic Mode", 
		LevelBrutal:    "Brutal Mode",
		LevelSavage:    "Savage Mode",
	}
	return names[cl.level]
}

func (cl *CynicalLogger) suggestCVE(vulnType string) {
	cveMap := map[string][]string{
		"sqli": {
			"CVE-2021-44228 (Log4Shell) - если используется Java",
			"CVE-2020-1472 (Zerologon) - для Active Directory",
			"CVE-2019-0708 (BlueKeep) - для RDP",
		},
		"xss": {
			"CVE-2021-44832 - для Apache Log4j",
			"CVE-2020-8597 - для PPP демона",
		},
		"rce": {
			"CVE-2021-44228 (Log4Shell) - критично!",
			"CVE-2021-34527 (PrintNightmare)",
			"CVE-2020-1472 (Zerologon)",
		},
		"lfi": {
			"CVE-2021-3156 (Baron Samedit) - sudo",
			"CVE-2020-14882 - Oracle WebLogic",
		},
	}
	
	vulnLower := strings.ToLower(vulnType)
	for key, cves := range cveMap {
		if strings.Contains(vulnLower, key) {
			color.Magenta("💡 Попробуй эти CVE:")
			for _, cve := range cves {
				color.White("   - %s", cve)
			}
			break
		}
	}
}

func (cl *CynicalLogger) addFinalComment() {
	finalComments := map[CynicalLevel][]string{
		LevelChill: {
			"✨ Работа выполнена качественно",
			"🎯 Все цели достигнуты",
			"📊 Результаты готовы к анализу",
		},
		LevelSarcastic: {
			"🎭 Админ может идти учиться безопасности",
			"🤡 Сервер защищен как картонный домик",
			"🤦‍♂️ Безопасность на уровне детского сада",
		},
		LevelBrutal: {
			"💀 Админ должен искать новую работу",
			"⚰️ Система разъебана морально",
			"🔥 Безопасность горит в аду",
		},
		LevelSavage: {
			"🖕 Ламер-админ может сосать хуи",
			"💣 Система взорвана к ебеням",
			"⚡ Админ идет нахуй увольняться",
		},
	}
	
	comments := finalComments[cl.level]
	comment := comments[randomInt(len(comments))]
	
	color.Magenta("\n💬 " + comment)
}


func (cl *CynicalLogger) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"session_id":       cl.sessionID,
		"target":          cl.target,
		"duration":        time.Since(cl.startTime),
		"vulnerabilities": cl.vulnsFound,
		"bypasses":        cl.bypassCount,
		"total_findings":  cl.findings,
		"level":           cl.getLevelName(),
		"encrypted":       cl.encrypted,
		"obfuscated":      cl.obfuscated,
	}
}


func generateSessionID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("ELITE_%X", b)
}

func randomInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 4)
	rand.Read(b)
	return int(uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3])) % max
}

func (cl *CynicalLogger) SetLevel(level CynicalLevel) {
	cl.level = level
	levelName := cl.getLevelName()
	color.Cyan("🔄 Switching to %s", levelName)
	cl.Info(fmt.Sprintf("Cynical level changed to: %s", levelName))
}