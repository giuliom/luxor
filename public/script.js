const button = document.querySelector("#hello-button");
const message = document.querySelector("#message");

button.addEventListener("click", () => {
  message.textContent = "Hello from JavaScript.";
});