var allCheckBoxes = document.getElementsByName('selected')
function MultipleChoice() {
    if (document.getElementById('mass').checked) {
        for (let i = 0; i < allCheckBoxes?.length; i++) {
            allCheckBoxes[i].checked = true
        }
    }
    else {
        for (let i = 0; i < allCheckBoxes?.length; i++) {
            allCheckBoxes[i].checked = false
        }
    }
}
function OneOfAll() {
    var check = true
    for (let i = 0; i < allCheckBoxes?.length; i++) {
        if (!allCheckBoxes[i].checked) {
            check = false
            break
        }
    }
    document.getElementById('mass').checked = check
}