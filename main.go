package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/kataras/go-sessions"
	"golang.org/x/crypto/bcrypt"
	// "os"
)

var db *sql.DB
var err error

// USER TYPE
type mhs struct {
	IDMhs       int
	Nim         string
	NameMhs     string
	PasswordMhs string
}

type dsn struct {
	IDDsn       int
	KodeDosen   string
	NameDsn     string
	PasswordDsn string
}

type adm struct {
	IDAdm       int
	Email       string
	NameAdm     string
	PasswordAdm string
}

type unt struct {
	IDUnit   int
	NameUnit string
	DescUnit string
}

type registrasi struct {
	IDRegistrasi int
	Nim          string
	DateRegist   string
	Status       string
	IDSertifikat int
	IDUnit       int
	IDNilai      int
}

type nila struct {
	IDNilai int
	Nilai   int
}

type sert struct {
	IDSertifikat int
	IDnilai      int
	ReleasedDate string
	FileName     string
}

// USER TYPE END

func connect_db() {
	db, err = sql.Open("mysql", "root:@tcp(127.0.0.1)/web_sertifikasi_alquran")

	if err != nil {
		log.Fatalln(err)
	}

	err = db.Ping()
	if err != nil {
		log.Fatalln(err)
	}
}

func routes() {
	http.Handle("/resources/css/", http.StripPrefix("/resources/css/", http.FileServer(http.Dir("./public/resources/css"))))
	http.Handle("/resources/js/", http.StripPrefix("/resources/js/", http.FileServer(http.Dir("./public/resources/js"))))
	http.Handle("/src/certificate/", http.StripPrefix("/src/certificate/", http.FileServer(http.Dir("./src/certificate/"))))

	//MAHASISWA SECTION
	http.HandleFunc("/", home)
	http.HandleFunc("/registration", registration)

	http.HandleFunc("/dosen", homeDosen)
	http.HandleFunc("/dosen/upload", dosenNilai)

	//ADMIN THINGS
	http.HandleFunc("/admin", adminDashboard)
	http.HandleFunc("/admin/edit-user", editUser)
	http.HandleFunc("/admin/delete-user", deleteUser)
	http.HandleFunc("/admin/create-user", createUser)
	http.HandleFunc("/admin/create-unit", createUnit)
	http.HandleFunc("/admin/delete-unit", deleteUnit)
	http.HandleFunc("/admin/edit-unit", editUnit)

	http.HandleFunc("/register", register) // dump, i need to delete it later
	http.HandleFunc("/login", login)
	http.HandleFunc("/logout", logout)
}

func getAllMahasiswa() []mhs {
	rows, err := db.Query(`SELECT * FROM mahasiswa`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var mahasiswa []mhs

	for rows.Next() {
		var mhsiswa mhs
		if err := rows.Scan(&mhsiswa.IDMhs, &mhsiswa.Nim, &mhsiswa.NameMhs, &mhsiswa.PasswordMhs); err != nil {
			panic(err)
		}

		mahasiswa = append(mahasiswa, mhsiswa)
	}

	return mahasiswa
}

func getAllDosen() []dsn {
	rows, err := db.Query(`SELECT * FROM dosen`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var dosen []dsn

	for rows.Next() {
		var dosent dsn
		if err := rows.Scan(&dosent.IDDsn, &dosent.KodeDosen, &dosent.NameDsn, &dosent.PasswordDsn); err != nil {
			panic(err)
		}

		dosen = append(dosen, dosent)
	}

	return dosen
}

func getAllAdmin() []adm {
	rows, err := db.Query(`SELECT * FROM admin`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var admin []adm

	for rows.Next() {
		var admint adm
		if err := rows.Scan(&admint.IDAdm, &admint.Email, &admint.NameAdm, &admint.PasswordAdm); err != nil {
			panic(err)
		}

		admin = append(admin, admint)
	}

	return admin
}

func getAllRegPending() []registrasi {
	rows, err := db.Query(`SELECT * FROM registrasi WHERE status="pending"`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var regPend []registrasi

	for rows.Next() {
		var regP registrasi
		if err := rows.Scan(&regP.IDRegistrasi, &regP.Nim, &regP.DateRegist, &regP.Status, &regP.IDSertifikat, &regP.IDUnit, &regP.IDNilai); err != nil {
			panic(err)
		}

		regPend = append(regPend, regP)
	}

	return regPend
}

func getAllRegGagal() []registrasi {
	rows, err := db.Query(`SELECT * FROM registrasi WHERE status="gagal"`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var regPend []registrasi

	for rows.Next() {
		var regP registrasi
		if err := rows.Scan(&regP.IDRegistrasi, &regP.Nim, &regP.DateRegist, &regP.Status, &regP.IDSertifikat, &regP.IDUnit, &regP.IDNilai); err != nil {
			panic(err)
		}

		regPend = append(regPend, regP)
	}

	return regPend
}

func getAllRegLulus() []registrasi {
	rows, err := db.Query(`SELECT * FROM registrasi WHERE status="lulus"`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var regPend []registrasi

	for rows.Next() {
		var regP registrasi
		if err := rows.Scan(&regP.IDRegistrasi, &regP.Nim, &regP.DateRegist, &regP.Status, &regP.IDSertifikat, &regP.IDUnit, &regP.IDNilai); err != nil {
			panic(err)
		}

		regPend = append(regPend, regP)
	}

	return regPend
}

func getAllUnit() []unt {
	rows, err := db.Query(`SELECT * FROM unit`)
	if err != nil {
		panic(err)
	}

	defer rows.Close()

	var units []unt

	for rows.Next() {
		var unite unt
		if err := rows.Scan(&unite.IDUnit, &unite.NameUnit, &unite.DescUnit); err != nil {
			panic(err)
		}

		units = append(units, unite)
	}

	return units
}

func main() {
	connect_db()
	routes()

	defer db.Close()

	fmt.Println("Server running on port :8000")
	http.ListenAndServe(":8000", nil)
}

func checkErr(w http.ResponseWriter, r *http.Request, err error) bool {
	if err != nil {

		fmt.Println(r.Host + r.URL.Path)

		http.Redirect(w, r, r.Host+r.URL.Path, 301)
		return false
	}

	return true
}

func QueryUser(nim string) mhs {
	var mahasiswa = mhs{}
	err = db.QueryRow(`
		SELECT id, 
		nim, 
		name, 
		password 
		FROM mahasiswa WHERE nim=?
		`, nim).
		Scan(
			&mahasiswa.IDMhs,
			&mahasiswa.Nim,
			&mahasiswa.NameMhs,
			&mahasiswa.PasswordMhs,
		)
	return mahasiswa
}

func QueryDosen(kodedosen string) dsn {
	var dosen = dsn{}
	err = db.QueryRow(`
		SELECT id, 
		kode_dosen, 
		name, 
		password 
		FROM dosen WHERE kode_dosen=?
		`, kodedosen).
		Scan(
			&dosen.IDDsn,
			&dosen.KodeDosen,
			&dosen.NameDsn,
			&dosen.PasswordDsn,
		)
	return dosen
}

func QueryAdmin(email string) adm {
	var admin = adm{}
	err = db.QueryRow(`
		SELECT id, 
		email, 
		name, 
		password 
		FROM admin WHERE email=?
		`, email).
		Scan(
			&admin.IDAdm,
			&admin.Email,
			&admin.NameAdm,
			&admin.PasswordAdm,
		)
	return admin
}

func QueryRegStats(nim string) registrasi {
	var registrasi = registrasi{}
	err = db.QueryRow(`
		SELECT id_registrasi, 
		nim, 
		registration_date, 
		status,
		id_sertifikat,
		id_unit,
		id_nilai 
		FROM registrasi WHERE nim=? ORDER BY id_registrasi DESC LIMIT 1
		`, nim).
		Scan(
			&registrasi.IDRegistrasi,
			&registrasi.Nim,
			&registrasi.DateRegist,
			&registrasi.Status,
			&registrasi.IDSertifikat,
			&registrasi.IDUnit,
			&registrasi.IDNilai,
		)
	if err != nil {
		fmt.Println(err)
	}
	// fmt.Println(registrasi)

	return registrasi
}

func QueryNilai(qnilai any) nila {
	var nilai = nila{}
	err = db.QueryRow(`
		SELECT id_nilai, 
		nilai
		FROM nilai WHERE id_nilai=?
		`, qnilai).
		Scan(
			&nilai.IDNilai,
			&nilai.Nilai,
		)
	return nilai
}

func QuerySerti(qserti any) sert {
	var serti = sert{}
	err = db.QueryRow(`
		SELECT id_sertifikat, 
		id_nilai,
		released_date,
		file_name
		FROM sertifikat WHERE id_sertifikat=?
		`, qserti).
		Scan(
			&serti.IDSertifikat,
			&serti.IDnilai,
			&serti.ReleasedDate,
			&serti.FileName,
		)
	return serti
}

func QueryUnit(qunit any) unt {
	var unit = unt{}
	err = db.QueryRow(`
		SELECT id_unit, 
		name,
		description
		FROM unit WHERE id_unit=?
		`, qunit).
		Scan(
			&unit.IDUnit,
			&unit.NameUnit,
			&unit.DescUnit,
		)
	return unit
}

func MaxIDNilai() string {
	var maxId string
	err := db.QueryRow(`SELECT MAX(id_nilai) FROM nilai`).Scan(&maxId)
	if err != nil {
		panic(err)
	}
	return maxId
}

func MaxIDSertifikat() string {
	var maxId string
	err := db.QueryRow(`SELECT MAX(id_sertifikat) FROM sertifikat`).Scan(&maxId)
	if err != nil {
		panic(err)
	}
	return maxId
}

//HANDLE FUNC

func register(w http.ResponseWriter, r *http.Request) { // WHY IM KEEPING THIS ALTOUGH I DONT USING IT ANYMORE
	if r.Method != "POST" {
		http.ServeFile(w, r, "public/register.html")
		return
	}

	username := r.FormValue("email")
	first_name := r.FormValue("first_name")
	// last_name := r.FormValue("last_name")
	password := r.FormValue("password")

	mahasiswa := QueryUser(username)

	if (mhs{}) == mahasiswa {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		if len(hashedPassword) != 0 && checkErr(w, r, err) {
			stmt, err := db.Prepare("INSERT INTO mahasiswa SET nim=?, name=?, password=?")
			if err == nil {
				_, err := stmt.Exec(&username, &first_name, &hashedPassword)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
		}
	} else {
		http.Redirect(w, r, "/register", 302)
	}
}

func login(w http.ResponseWriter, r *http.Request) { //WELL IDK WHY DOES IT WORKS FINE
	session := sessions.Start(w, r)
	if len(session.GetString("username")) != 0 && checkErr(w, r, err) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if r.Method != "POST" {
		http.ServeFile(w, r, "public/login.html")
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	usertype := r.FormValue("usertype")

	switch usertype {
	case "mahasiswa":
		mahasiswa := QueryUser(username)

		//deskripsi dan compare password
		var password_tes = bcrypt.CompareHashAndPassword([]byte(mahasiswa.PasswordMhs), []byte(password))

		if password_tes == nil {
			//login success
			session := sessions.Start(w, r)
			session.Set("username", mahasiswa.Nim)
			session.Set("name", mahasiswa.NameMhs)
			session.Set("usertype", usertype)
			http.Redirect(w, r, "/", http.StatusFound)
		} else {
			//login failed
			http.Redirect(w, r, "/login", http.StatusFound)
		}

	case "dosen":
		dosen := QueryDosen(username)

		//deskripsi dan compare password
		var password_tes = bcrypt.CompareHashAndPassword([]byte(dosen.PasswordDsn), []byte(password))

		if password_tes == nil {
			//login success
			session := sessions.Start(w, r)
			session.Set("username", dosen.KodeDosen)
			session.Set("name", dosen.NameDsn)
			session.Set("usertype", usertype)
			http.Redirect(w, r, "/dosen", http.StatusFound)
		} else {
			//login failed
			http.Redirect(w, r, "/login", http.StatusFound)
		}

	case "admin":
		admin := QueryAdmin(username)

		//deskripsi dan compare password
		var password_tes = bcrypt.CompareHashAndPassword([]byte(admin.PasswordAdm), []byte(password))

		if password_tes == nil {
			//login success
			session := sessions.Start(w, r)
			session.Set("username", admin.Email)
			session.Set("name", admin.NameAdm)
			session.Set("usertype", usertype)
			http.Redirect(w, r, "/admin", http.StatusFound)
		} else {
			//login failed
			http.Redirect(w, r, "/login", http.StatusFound)
		}

	default:
		http.Redirect(w, r, "/login", http.StatusFound)
	}

}

// MAHASISWA

func home(w http.ResponseWriter, r *http.Request) { // coming soon
	session := sessions.Start(w, r)
	// if session.GetString("usertype") != "mahasiswa" {
	// 	http.Redirect(w, r, "/login", 301)
	// 	return
	// }

	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}
	var belumDaftar bool
	var lulus bool
	var gagal bool

	unit := getAllUnit()
	nim := session.GetString("username")
	regStatus := QueryRegStats(nim)
	if regStatus.Status == "lulus" {
		lulus = true
	} else if regStatus.Status == "pending" {
		belumDaftar = false
	} else if regStatus.Status == "gagal" {
		gagal = true
	} else {
		belumDaftar = true
	}
	// fmt.Println(regStatus.Status)
	// fmt.Println(status)

	funcMap := template.FuncMap{
		"increment": func(i int) int {
			i += 1
			return i
		},

		"queryserti": func(nim string) string {
			reg := QueryRegStats(nim)

			qrow := QuerySerti(reg.IDSertifikat)
			return qrow.FileName
		},
	}

	var data = map[string]any{
		"name":        session.GetString("name"),
		"nim":         nim,
		"unit":        unit,
		"belumDaftar": belumDaftar,
		"lulus":       lulus,
		"gagal":       gagal,
	}

	var t = template.New("index.html").Funcs(funcMap)

	t, err = t.ParseFiles("public/home/mahasiswa/index.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

}

func registration(w http.ResponseWriter, r *http.Request) { // working on
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	timeNow := time.Now().Format(time.DateTime)

	nim := r.FormValue("usernim")
	// fmt.Println(nim)
	strIdUnit := r.FormValue("unit")
	// println(strIdUnit)
	idUnit, err := strconv.Atoi(strIdUnit)
	if err != nil {
		log.Fatal(err)
	}

	nilai, err := db.Prepare("INSERT INTO nilai SET nilai=?")
	if err == nil {
		_, err = nilai.Exec(0)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	sertifikat, err := db.Prepare("INSERT INTO sertifikat SET id_nilai=?")
	if err == nil {

		intLatestNilai, _ := strconv.Atoi(MaxIDNilai())
		_, err = sertifikat.Exec(intLatestNilai)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	regist, err := db.Prepare("INSERT INTO registrasi SET nim=?, registration_date=?, status=?, id_sertifikat=?, id_unit=?, id_nilai=?")
	if err == nil {

		intLatestNilai, _ := strconv.Atoi(MaxIDNilai())
		intLatestSerti, _ := strconv.Atoi(MaxIDSertifikat())

		_, err = regist.Exec(nim, timeNow, "pending", intLatestSerti, idUnit, intLatestNilai)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

}

// DOSEN

func homeDosen(w http.ResponseWriter, r *http.Request) { //uhh this ma home work
	session := sessions.Start(w, r)
	// if session.GetString("usertype") != "dosen" {
	// 	return
	// }

	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	listPending := getAllRegPending()
	listGagal := getAllRegGagal()
	listLulus := getAllRegLulus()

	funcMap := template.FuncMap{
		"increment": func(i int) int {
			i += 1
			return i
		},

		"querynama": func(nim string) string {
			qrow := QueryUser(nim)
			return qrow.NameMhs
		},

		"querynilai": func(id any) int {
			qrow := QueryNilai(id)
			return qrow.Nilai
		},

		"queryserti": func(id any) string {
			qrow := QuerySerti(id)
			return qrow.FileName
		},

		"querysertidate": func(id any) string {
			qrow := QuerySerti(id)
			return qrow.ReleasedDate
		},

		"queryunit": func(id any) string {
			qrow := QueryUnit(id)
			return qrow.NameUnit
		},
	}

	var data = map[string]any{
		"name":    session.GetString("name"),
		"pending": listPending,
		"gagal":   listGagal,
		"lulus":   listLulus,
	}
	var t = template.New("index.html").Funcs(funcMap)

	t, err = t.ParseFiles("public/home/dosen/index.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func dosenNilai(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Redirect(w, r, "/dosen", 301)
		return
	}

	id, err := strconv.Atoi(r.URL.Query().Get("q"))
	if err != nil {
		panic(err)
	}

	status := r.FormValue("status")
	nilai := r.FormValue("nilai")

	switch status {
	case "lulus":
		// func (r *Request) ParseMultipartForm(maxMemory int64) error
		r.ParseMultipartForm(10)
		// func (r *Request) FormFile(key string) (multipart.File, *multipart.FileHeader, error)
		file, fileHeader, err := r.FormFile("serti")
		if err != nil {
			fmt.Println(err)
			return
		}
		defer file.Close()
		// fmt.Printf("fileHeader.Filename: %v\n", fileHeader.Filename)
		// fmt.Printf("fileHeader.Size: %v\n", fileHeader.Size)
		// fmt.Printf("fileHeader.Header: %v\n", fileHeader.Header)

		// tempFile, err := ioutil.TempFile("images", "upload-*.png")
		contentType := fileHeader.Header["Content-Type"][0]
		fmt.Println("Content Type:", contentType)
		var osFile *os.File
		// func TempFile(dir, pattern string) (f *os.File, err error)
		if contentType == "application/pdf" {
			osFile, err = ioutil.TempFile("src/certificate", "*.pdf")
		}
		fmt.Println("error:", err)
		defer osFile.Close()

		// func ReadAll(r io.Reader) ([]byte, error)
		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			fmt.Println(err)
		}
		// func (f *File) Write(b []byte) (n int, err error)

		osFile.Write(fileBytes)
		fmt.Println(osFile.Name())
		filename := strings.Trim(osFile.Name(), `src/etifa\.pd`)
		fmt.Println(filename)

		stmt, err := db.Prepare("UPDATE registrasi SET status=? WHERE id_registrasi=?")
		if err == nil {
			_, err = stmt.Exec(&status, &id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		idNilai := r.FormValue("idn")
		stmt2, err := db.Prepare("UPDATE nilai SET nilai=? 	WHERE id_nilai=?")
		if err == nil {
			_, err = stmt2.Exec(&nilai, &idNilai)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		timeNow := time.Now().Format(time.DateTime)
		idSerti := r.FormValue("ids")
		stmt3, err := db.Prepare("UPDATE sertifikat SET released_date=?, file_name=? WHERE id_sertifikat=?")
		if err == nil {
			_, err = stmt3.Exec(&timeNow, &filename, &idSerti)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/dosen", 301)
		return

	case "gagal":

		stmt, err := db.Prepare("UPDATE registrasi SET status=? WHERE id_registrasi=?")
		if err == nil {
			_, err = stmt.Exec(&status, &id)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		idNilai := r.FormValue("idn")
		stmt2, err := db.Prepare("UPDATE nilai SET nilai=? 	WHERE id_nilai=?")
		if err == nil {
			_, err = stmt2.Exec(&nilai, &idNilai)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		http.Redirect(w, r, "/dosen", 301)
		return

	default:

	}

	http.Redirect(w, r, "/dosen", 301)
	return
}

// ADMIN DAN FUNCTION-FUNCTION NYA (i think it's done)

func adminDashboard(w http.ResponseWriter, r *http.Request) { //NO ERROR FOR NOW
	session := sessions.Start(w, r)
	// if session.GetString("usertype") != "admin" {
	// 	return
	// }

	if len(session.GetString("username")) == 0 {
		http.Redirect(w, r, "/login", 301)
	}

	mahasiswa := getAllMahasiswa()
	dosen := getAllDosen()
	admin := getAllAdmin()
	unit := getAllUnit()

	funcMap := template.FuncMap{
		"increment": func(i int) int {
			i += 1
			return i
		},
	}

	var data = map[string]interface{}{
		"username":  session.GetString("name"),
		"message":   "Welcome to the Go !",
		"mahasiswa": mahasiswa,
		"dosen":     dosen,
		"admin":     admin,
		"unit":      unit,
	}

	var t = template.New("index.html").Funcs(funcMap)

	t, err = t.ParseFiles("public/home/admin/index.html")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	err = t.Execute(w, data)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func editUser(w http.ResponseWriter, r *http.Request) { //NO ERROR SO FAR
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	userType := r.URL.Query().Get("ut")
	if userType == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("q")
	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	name := r.FormValue("name")
	username := r.FormValue("username")
	password := r.FormValue("password")

	switch userType {
	case "admin":
		if len(password) != 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("UPDATE admin SET email=?, name=?, password=? WHERE id=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword, &id)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			stmt, err := db.Prepare("UPDATE admin SET email=?, name=? WHERE id=?")
			if err == nil {
				_, err = stmt.Exec(&username, &name, &id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}

	case "dosen":
		if len(password) != 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("UPDATE dosen SET kode_dosen=?, name=?, password=? WHERE id=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword, &id)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			stmt, err := db.Prepare("UPDATE dosen SET kode_dosen=?, name=? WHERE id=?")
			if err == nil {
				_, err = stmt.Exec(&username, &name, &id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}

	case "mahasiswa":
		if len(password) != 0 {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("UPDATE mahasiswa SET nim=?, name=?, password=? WHERE id=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword, &id)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			stmt, err := db.Prepare("UPDATE mahasiswa SET nim=?, name=? WHERE id=?")
			if err == nil {
				_, err = stmt.Exec(&username, &name, &id)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				http.Redirect(w, r, "/admin", http.StatusSeeOther)
				return
			}
		}
	}
}

func deleteUser(w http.ResponseWriter, r *http.Request) { //NO ERROR SO FAR
	userType := r.URL.Query().Get("ut")
	if userType == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
	idString := r.URL.Query().Get("q")
	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", userType)

	_, errs := db.Exec(query, id)
	if errs != nil {
		panic(errs)
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func createUser(w http.ResponseWriter, r *http.Request) { //NO ERROR SO FAR
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	username := r.FormValue("username")
	name := r.FormValue("name")
	password := r.FormValue("password")

	usertype := r.FormValue("usertype")

	switch usertype {
	case "admin":
		admin := QueryAdmin(username)

		if (adm{}) == admin {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("INSERT INTO admin SET email=?, name=?, password=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}

	case "dosen":
		dosen := QueryDosen(username)

		if (dsn{}) == dosen {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("INSERT INTO dosen SET kode_dosen=?, name=?, password=?")
				if err == nil {
					_, err = stmt.Exec(&username, &name, &hashedPassword)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}

	case "mahasiswa":

		mahasiswa := QueryUser(username)

		if (mhs{}) == mahasiswa {
			hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

			if len(hashedPassword) != 0 && checkErr(w, r, err) {
				stmt, err := db.Prepare("INSERT INTO mahasiswa SET nim=?, name=?, password=?")
				if err == nil {
					_, err := stmt.Exec(&username, &name, &hashedPassword)
					if err != nil {
						http.Error(w, err.Error(), http.StatusInternalServerError)
						return
					}

					http.Redirect(w, r, "/admin", http.StatusSeeOther)
					return
				}
			}
		} else {
			http.Redirect(w, r, "/admin", http.StatusFound)
		}
	}

}

func deleteUnit(w http.ResponseWriter, r *http.Request) { // NO ERROR SO FAR
	idString := r.URL.Query().Get("q")
	if idString == "" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	_, errs := db.Exec("DELETE FROM unit WHERE id_unit = ?", id)
	if errs != nil {
		panic(errs)
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func createUnit(w http.ResponseWriter, r *http.Request) { //NO ERROR SO FAR
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	name := r.FormValue("nameunit")
	description := r.FormValue("unitdesc")

	stmt, err := db.Prepare("INSERT INTO unit SET name=?, description=?")
	if err == nil {
		_, err = stmt.Exec(&name, &description)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
}

func editUnit(w http.ResponseWriter, r *http.Request) { //WORKED
	if r.Method != "POST" {
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}

	idString := r.URL.Query().Get("q")
	id, err := strconv.Atoi(idString)
	if err != nil {
		panic(err)
	}

	name := r.FormValue("nameunit")
	desc := r.FormValue("unitdesc")

	stmt, err := db.Prepare("UPDATE unit SET name=?, description=? WHERE id_unit=?")
	if err == nil {
		_, err = stmt.Exec(&name, &desc, &id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/admin", http.StatusSeeOther)
		return
	}
}

func logout(w http.ResponseWriter, r *http.Request) { //WORKS NORMALLY
	session := sessions.Start(w, r)
	session.Clear()
	sessions.Destroy(w, r)
	http.Redirect(w, r, "/", 302)
}
