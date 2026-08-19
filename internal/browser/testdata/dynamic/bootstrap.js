document.cookie = "browser_fixture_cookie=fake-cookie-value; SameSite=Lax";
document.write(
  '<script src="/dynamic/injected.js?credential=fake-script-credential#fake-script-fragment"><\/script>' +
  '<iframe src="/dynamic/frame?session=fake-frame-session#fake-frame-fragment"></iframe>'
);
