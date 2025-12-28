/* =============================
   Form Elements / عناصر فرم
============================= */
const form = document.getElementById('registerForm');
const tabs = document.querySelectorAll('.tab');
const usernameInput = document.getElementById('username');
const fullNameInput = document.getElementById('fullName');
const emailInput = document.getElementById('email');
const passwordInput = document.getElementById('password');
const registerBtn = document.getElementById('registerBtn');

const loginForm = document.getElementById('loginForm');
const loginEmailInput = document.getElementById('loginEmail');
const loginPasswordInput = document.getElementById('loginPassword');
const loginBtn = document.getElementById('loginBtn');

const usernameError = document.getElementById('usernameError');
const fullNameError = document.getElementById('fullNameError');
const emailError = document.getElementById('emailError');

const ruleStrength = document.getElementById('ruleStrength');
const strengthLabel = document.getElementById('strengthLabel');
const ruleNoNameEmail = document.getElementById('ruleNoNameEmail');
const ruleMinLength = document.getElementById('ruleMinLength');
const ruleNumberSymbol = document.getElementById('ruleNumberSymbol');

const successMessage = document.getElementById('successMessage');
const success = document.getElementById('loginSuccess');
const error = document.getElementById('loginError');

const togglePasswordSignup = document.getElementById('togglePasswordSignup');
const togglePasswordLogin = document.getElementById('togglePasswordLogin');

/* =============================
   Password Hashing / هش کردن رمز
============================= */
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/* =============================
   Tab Switch / تغییر تب‌ها
============================= */
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => {
    tabs.forEach((t) => t.classList.remove('active'));
    tab.classList.add('active');

    if (index === 0) {
      registerForm.classList.add('active');
      loginForm.classList.remove('active');
    } else {
      registerForm.classList.remove('active');
      loginForm.classList.add('active');
    }
  });
});

/* =============================
   Login Button Enable / فعال شدن دکمه ورود
============================= */
function updateLoginButton() {
  const email = loginEmailInput.value.trim();
  const password = loginPasswordInput.value.trim();
  loginBtn.disabled = !(email && password);
}
loginEmailInput.addEventListener('input', updateLoginButton);
loginPasswordInput.addEventListener('input', updateLoginButton);

/* =============================
   Login Handler / مدیریت ورود
============================= */
loginBtn.addEventListener('click', async (event) => {
  event.preventDefault();
  const stored = JSON.parse(localStorage.getItem('simpleflowUser'));
  const email = loginEmailInput.value.trim();
  const password = loginPasswordInput.value.trim();

  success.style.opacity = '0';
  error.style.opacity = '0';

  if (!stored) {
    error.textContent = 'No account found. Please sign up first.';
    error.style.opacity = '1';
    return;
  }

  const hashedInput = await hashPassword(password);

  if (stored.email === email && stored.passwordHash === hashedInput) {
    success.textContent = `Welcome, ${stored.fullName}!`;
    success.style.opacity = '1';
  } else {
    error.textContent = 'Incorrect email or password';
    error.style.opacity = '1';
  }
});

/* =============================
   Helper Functions / توابع کمکی
============================= */
function setInputState(input, isValid, messageElement, message = '') {
  if (isValid) {
    input.classList.remove('invalid');
    input.classList.add('valid');
    if (messageElement) messageElement.textContent = '';
  } else {
    input.classList.remove('valid');
    input.classList.add('invalid');
    if (messageElement) messageElement.textContent = message;
  }
}

function setRuleState(ruleEl, isValid) {
  ruleEl.classList.remove('valid', 'invalid');
  ruleEl.classList.add(isValid ? 'valid' : 'invalid');
}

/* =============================
   Username Validation / اعتبارسنجی نام کاربری
============================= */
function validateUsername() {
  const value = usernameInput.value.trim();
  let valid = true;
  let message = '';

  if (value.length < 3 || value.length > 15) {
    valid = false;
    message = 'Username must be between 3 and 15 characters';
  } else if (!/^[a-zA-Z0-9]+$/.test(value)) {
    valid = false;
    message = 'Username can only contain letters and numbers';
  }

  setInputState(usernameInput, valid, usernameError, message);
  return valid;
}

/* =============================
   Full Name Validation / اعتبارسنجی نام کامل
============================= */
function validateFullName() {
  const value = fullNameInput.value.trim();
  let valid = true;
  let message = '';

  if (!value) {
    valid = false;
    message = 'Please enter your full name';
  } else if (!/^[A-Za-z\s]+$/.test(value)) {
    valid = false;
    message = 'Full name must contain only letters and spaces';
  } else {
    const parts = value.split(/\s+/).filter(Boolean);
    if (parts.length < 2) {
      valid = false;
      message = 'Please enter your full name';
    }
  }

  setInputState(fullNameInput, valid, fullNameError, message);
  return valid;
}

/* =============================
   Email Validation / اعتبارسنجی ایمیل
============================= */
function validateEmail() {
  const value = emailInput.value.trim();
  let valid = true;
  let message = '';
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

  if (!emailRegex.test(value)) {
    valid = false;
    message = 'Please enter a valid email address';
  }

  setInputState(emailInput, valid, emailError, message);
  return valid;
}

/* =============================
   Password Helpers / کمک‌کننده‌های رمز عبور
============================= */
function passwordContainsNameOrEmail(password, fullName, email) {
  const pwd = password.toLowerCase();

  if (fullName) {
    const parts = fullName.toLowerCase().split(/\s+/).filter((p) => p.length > 1);
    for (const part of parts) if (pwd.includes(part)) return true;
  }

  if (email) {
    const lowerEmail = email.toLowerCase();
    const [local] = lowerEmail.split('@');
    const emailParts = [local, ...lowerEmail.split(/[.@_+-]/)].filter((p) => p.length > 1);
    for (const part of emailParts) if (pwd.includes(part)) return true;
  }

  return false;
}

/* =============================
   Password Validation / اعتبارسنجی رمز
============================= */
function validatePassword() {
  const password = passwordInput.value;
  const fullName = fullNameInput.value.trim();
  const email = emailInput.value.trim();

  if (password.length === 0) {
    ruleMinLength.classList.remove('valid', 'invalid');
    ruleNumberSymbol.classList.remove('valid', 'invalid');
    ruleNoNameEmail.classList.remove('valid', 'invalid');
    ruleStrength.classList.remove('valid', 'invalid');
    strengthLabel.textContent = 'Weak';
    passwordInput.classList.remove('valid', 'invalid');
    return false;
  }

  const minLengthOk = password.length >= 8;
  const hasNumber = /\d/.test(password);
  const hasSymbol = /[!@#$%^&*()\-_=+[{\]}\\|;:'",<.>/?`~]/.test(password);
  const numberOrSymbolOk = hasNumber || hasSymbol;
  const containsNameOrEmail = passwordContainsNameOrEmail(password, fullName, email);
  const noNameEmailOk = !containsNameOrEmail;

  let passedRules = 0;
  if (minLengthOk) passedRules++;
  if (numberOrSymbolOk) passedRules++;
  if (noNameEmailOk) passedRules++;

  let strengthText = 'Weak';
  if (passedRules === 3 && password.length >= 10) strengthText = 'Strong';
  else if (passedRules >= 2) strengthText = 'Medium';

  strengthLabel.textContent = strengthText;

  setRuleState(ruleMinLength, minLengthOk);
  setRuleState(ruleNumberSymbol, numberOrSymbolOk);
  setRuleState(ruleNoNameEmail, noNameEmailOk);
  setRuleState(ruleStrength, minLengthOk && numberOrSymbolOk && noNameEmailOk);
  setInputState(passwordInput, minLengthOk && numberOrSymbolOk && noNameEmailOk, null, '');

  return minLengthOk && numberOrSymbolOk && noNameEmailOk;
}

/* =============================
   Submit Button Enable / فعال کردن دکمه ثبت نام
============================= */
function updateSubmitButton() {
  const allValid =
    usernameInput.classList.contains('valid') &&
    fullNameInput.classList.contains('valid') &&
    emailInput.classList.contains('valid') &&
    passwordInput.classList.contains('valid');

  registerBtn.disabled = !allValid;
}

/* =============================
   Event Listeners / رویدادها
============================= */
usernameInput.addEventListener('input', () => { validateUsername(); updateSubmitButton(); });
fullNameInput.addEventListener('input', () => { validateFullName(); validatePassword(); updateSubmitButton(); });
emailInput.addEventListener('input', () => { validateEmail(); validatePassword(); updateSubmitButton(); });
passwordInput.addEventListener('input', () => { validatePassword(); updateSubmitButton(); });

/* Show/Hide Password / نمایش/مخفی کردن رمز */
if (togglePasswordSignup) {
  togglePasswordSignup.addEventListener('click', () => {
    const input = document.getElementById('password');
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    togglePasswordSignup.textContent = isPassword ? 'Hide' : 'Show';
  });
}
if (togglePasswordLogin) {
  togglePasswordLogin.addEventListener('click', () => {
    const input = document.getElementById('loginPassword');
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    togglePasswordLogin.textContent = isPassword ? 'Hide' : 'Show';
  });
}

/* =============================
   Registration Submit / ثبت نام
============================= */
form.addEventListener('submit', async (event) => {
  event.preventDefault();

  if (registerBtn.disabled) {
    successMessage.style.opacity = '0';
    return;
  }

  const rawPassword = passwordInput.value.trim();
  const hashedPassword = await hashPassword(rawPassword);

  const data = {
    username: usernameInput.value.trim(),
    fullName: fullNameInput.value.trim(),
    email: emailInput.value.trim(),
    password: '*'.repeat(rawPassword.length)
  };

  console.log('Registration data:', data);

  // Save hashed password / ذخیره هش شده
  const storedUser = {
    username: data.username,
    fullName: data.fullName,
    email: data.email,
    passwordHash: hashedPassword
  };
  localStorage.setItem('simpleflowUser', JSON.stringify(storedUser));

  successMessage.style.opacity = '1';

  // Reset form / ریست فرم
  form.reset();
  usernameInput.classList.remove('valid', 'invalid');
  fullNameInput.classList.remove('valid', 'invalid');
  emailInput.classList.remove('valid', 'invalid');
  passwordInput.classList.remove('valid', 'invalid');
  usernameError.textContent = '';
  fullNameError.textContent = '';
  emailError.textContent = '';
  ruleMinLength.classList.remove('valid', 'invalid');
  ruleNumberSymbol.classList.remove('valid', 'invalid');
  ruleNoNameEmail.classList.remove('valid', 'invalid');
  ruleStrength.classList.remove('valid', 'invalid');
  strengthLabel.textContent = 'Weak';
  passwordInput.classList.remove('valid', 'invalid');
  registerBtn.disabled = true;
});

/* =============================
   Forgot Password / فراموشی رمز عبور
============================= */
document.getElementById('forgotPasswordLink').addEventListener('click', () => {
  alert('Password recovery flow is not implemented in this demo.');
});
