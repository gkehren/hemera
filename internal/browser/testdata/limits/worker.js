Promise.all([
  fetch("/limits/worker-api-one"),
  fetch("/limits/worker-api-two")
]);
