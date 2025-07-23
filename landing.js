// Landing Page JavaScript
document.addEventListener("DOMContentLoaded", () => {
  // Mobile menu toggle
  const mobileMenuToggle = document.querySelector(".mobileMenuToggle")
  const mainMenu = document.querySelector(".main-menu")

  if (mobileMenuToggle && mainMenu) {
    mobileMenuToggle.addEventListener("click", () => {
      mainMenu.style.display = mainMenu.style.display === "block" ? "none" : "block"
    })
  }

  // Smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault()
      const target = document.querySelector(this.getAttribute("href"))
      if (target) {
        target.scrollIntoView({
          behavior: "smooth",
          block: "start",
        })
      }
    })
  })

  // Video placeholder click handler
  const videoPlaceholder = document.querySelector(".video-placeholder")
  if (videoPlaceholder) {
    videoPlaceholder.addEventListener("click", () => {
      // You can add video modal or redirect logic here
      console.log("Video clicked - add your video logic here")
    })
  }

  // FAQ accordion functionality
  const faqItems = document.querySelectorAll(".faq-item")
  faqItems.forEach((item) => {
    const question = item.querySelector(".faq-question")
    question.addEventListener("click", () => {
      // Close other open items
      faqItems.forEach((otherItem) => {
        if (otherItem !== item && otherItem.hasAttribute("open")) {
          otherItem.removeAttribute("open")
        }
      })
    })
  })

  // Add scroll effect to header
  let lastScrollTop = 0
  const header = document.querySelector(".header")

  window.addEventListener("scroll", () => {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop

    if (scrollTop > lastScrollTop && scrollTop > 100) {
      // Scrolling down
      header.style.transform = "translateY(-100%)"
    } else {
      // Scrolling up
      header.style.transform = "translateY(0)"
    }

    lastScrollTop = scrollTop
  })

  // Add animation on scroll
  const observerOptions = {
    threshold: 0.1,
    rootMargin: "0px 0px -50px 0px",
  }

  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry) => {
      if (entry.isIntersecting) {
        entry.target.classList.add("fadeIn")
      }
    })
  }, observerOptions)

  // Observe elements for animation
  document.querySelectorAll(".feature-item, .advantage-item, .how-it-works-item, .faq-item").forEach((el) => {
    observer.observe(el)
  })

  // Redirect all login/signup buttons to index.html
  document.querySelectorAll('a[href="index.html"]').forEach((link) => {
    link.addEventListener("click", (e) => {
      e.preventDefault()
      window.location.href = "index.html"
    })
  })
})

// Add some interactive effects
document.addEventListener("mousemove", (e) => {
  const heroSection = document.querySelector(".hero-section")
  if (heroSection) {
    const rect = heroSection.getBoundingClientRect()
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top

    if (x >= 0 && x <= rect.width && y >= 0 && y <= rect.height) {
      const xPercent = (x / rect.width) * 100
      const yPercent = (y / rect.height) * 100

      heroSection.style.background = `
                radial-gradient(circle at ${xPercent}% ${yPercent}%, 
                rgba(255,255,255,0.1) 0%, 
                transparent 50%), 
                linear-gradient(135deg, var(--color-primary-dark), var(--color-primary))
            `
    }
  }
})
