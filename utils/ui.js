/*=========================
   BUTTON LOADER
========================= */
export function setButtonLoading(button, state) {
  if (!button) return;

  if (state) {
    button.disabled = true;
    button.dataset.originalText = button.innerHTML;

    button.innerHTML = `
      <div class="loader active">
        <span></span><span></span><span></span>
      </div>
    `;
  } else {
    button.disabled = false;
    button.innerHTML = button.dataset.originalText || "Submit";
  }
}

/* =========================
   PAGE LOADER (SPINNER)
========================= */
export function showPageLoader(container) {
  if (!container) return;

  container.innerHTML = `
    <div class="page-loader">
      <div class="spinner"></div>
    </div>
  `;
}

export function hidePageLoader(container) {
  if (!container) return;
  container.innerHTML = "";
}

/* =========================
   SKELETON LOADER
========================= */
export function showSkeleton(container, count = 5) {
  if (!container) return;

  let skeletons = "";

  for (let i = 0; i < count; i++) {
    skeletons += `
      <div class="skeleton-card">
        <div class="skeleton-avatar"></div>
        <div class="skeleton-text"></div>
      </div>
    `;
  }

  container.innerHTML = skeletons;
}

/* =========================
   TOAST NOTIFICATION
========================= */
export function showToast(message, type = "success") {
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.innerText = message;

  document.body.appendChild(toast);

  setTimeout(() => toast.classList.add("show"), 100);

  setTimeout(() => {
    toast.classList.remove("show");
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

/* =========================
   MODALS
========================= */
export function setupImageModal(modal, imgElement) {
  if (!modal || !imgElement) return;

  modal.addEventListener("click", (e) => {
    if (e.target === modal) {
      modal.classList.remove("show");
      imgElement.src = "";
    }
  });
}

export function setupCloseOnOutside(modal) {
  if (!modal) return;

  modal.addEventListener("click", (e) => {
    if (e.target === modal) {
      modal.classList.remove("show");
    }
  });
}

/* =========================
   DEFAULT UI OBJECT EXPORT
========================= */
const UI = {
  setButtonLoading,
  showPageLoader,
  hidePageLoader,
  showSkeleton,
  showToast,
  setupImageModal,
  setupCloseOnOutside
};

export default UI;