
fetch('scripts/sidebar.html')
.then(response=> response.text())
.then(text=> document.getElementById('sidebar').innerHTML = text);

page = window.location.href;
page_basename = page.substr(page.lastIndexOf("/") + 1);
page_noext = page_basename.substr(0,page_basename.lastIndexOf('.'));

alert(page_noext);

toedit = document.querySelector('[name="'+page_noext+'"]');
toedit.classList.add('active');


fetch('rtd-msg.html')
.then(response=> response.text())
.then(text=> document.getElementById('rtd-msg').innerHTML = text);
