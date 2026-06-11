const button = document.querySelector("#hello-button");
const message = document.querySelector("#message");

button.addEventListener("click", async () => {
  button.disabled = true;
  message.textContent = "Asking the server...";

  try {
    const response = await fetch("/api/time");

    if (!response.ok) {
      throw new Error(`Server returned ${response.status}`);
    }

    const data = await response.json();
    message.textContent = `Server time: ${data.server_time}`;
  } catch (error) {
    message.textContent = "Could not ask the server for the time.";
  } finally {
    button.disabled = false;
  }
});