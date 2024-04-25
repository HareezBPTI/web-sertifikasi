const sManageMahasiswa = document.querySelector("#manage-umahasiswa");
const sManageDosen = document.querySelector("#manage-udosen");
const sManageAdmin = document.querySelector("#manage-uadmin");

sManageMahasiswa.addEventListener("click", function () {
    sManageMahasiswa.classList.add("active");
    sManageDosen.classList.remove("active");
    sManageAdmin.classList.remove("active");

    var tabMahasiswa = document.querySelector("#manage-table-mahasiswa");
    var tabDosen = document.querySelector("#manage-table-dosen");
    var tabAdmin = document.querySelector("#manage-table-admin");

    tabMahasiswa.classList.remove("hidden");
    tabDosen.classList.add("hidden");
    tabAdmin.classList.add("hidden");
});

sManageDosen.addEventListener("click", function () {
    sManageMahasiswa.classList.remove("active");
    sManageDosen.classList.add("active");
    sManageAdmin.classList.remove("active");

    var tabMahasiswa = document.querySelector("#manage-table-mahasiswa");
    var tabDosen = document.querySelector("#manage-table-dosen");
    var tabAdmin = document.querySelector("#manage-table-admin");

    tabMahasiswa.classList.add("hidden");
    tabDosen.classList.remove("hidden");
    tabAdmin.classList.add("hidden");
});

sManageAdmin.addEventListener("click", function () {
    sManageMahasiswa.classList.remove("active");
    sManageDosen.classList.remove("active");
    sManageAdmin.classList.add("active");

    var tabMahasiswa = document.querySelector("#manage-table-mahasiswa");
    var tabDosen = document.querySelector("#manage-table-dosen");
    var tabAdmin = document.querySelector("#manage-table-admin");

    tabMahasiswa.classList.add("hidden");
    tabDosen.classList.add("hidden");
    tabAdmin.classList.remove("hidden");
});


const toggleCreateUser = document.querySelector("#create-user");
const closeCreateUser = document.querySelector("#close-create-user");

toggleCreateUser.addEventListener("click", function() {
    
    //disabling the toggle button
    toggleCreateUser.setAttribute("disabled", "");

    var createUserForm = document.querySelector("#create-user-form");
    var sidebar = document.querySelector("#mainSidebar");
    var main = document.querySelector("#mainContent");

    createUserForm.classList.remove("hidden");
    sidebar.classList.add("blur-sm");
    main.classList.add("blur-sm");
});

closeCreateUser.addEventListener("click", function() {

    //enable the toggle button
    toggleCreateUser.removeAttribute("disabled");

    var createUserForm = document.querySelector("#create-user-form");
    var sidebar = document.querySelector("#mainSidebar");
    var main = document.querySelector("#mainContent");

    createUserForm.classList.add("hidden");
    sidebar.classList.remove("blur-sm");
    main.classList.remove("blur-sm");
});

const toggleCreateUnit = document.querySelector("#create-unit");
const closeCreateUnit = document.querySelector("#close-create-unit");

toggleCreateUnit.addEventListener("click", function() {
    
    //disabling the toggle button
    toggleCreateUnit.setAttribute("disabled", "");

    var createUnitForm = document.querySelector("#create-unit-form");
    var sidebar = document.querySelector("#mainSidebar");
    var main = document.querySelector("#mainContent");

    createUnitForm.classList.remove("hidden");
    sidebar.classList.add("blur-sm");
    main.classList.add("blur-sm");
});

closeCreateUnit.addEventListener("click", function() {

    //enable the toggle button
    toggleCreateUnit.removeAttribute("disabled");

    var createUnitForm = document.querySelector("#create-unit-form");
    var sidebar = document.querySelector("#mainSidebar");
    var main = document.querySelector("#mainContent");

    createUnitForm.classList.add("hidden");
    sidebar.classList.remove("blur-sm");
    main.classList.remove("blur-sm");
});