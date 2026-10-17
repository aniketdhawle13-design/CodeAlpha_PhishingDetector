document.addEventListener("DOMContentLoaded", () => {

    console.log("PhishGuard AI Loaded");

    const cards =
    document.querySelectorAll(".glass-card");

    cards.forEach(card => {

        card.addEventListener("mouseenter", () => {
            card.style.transform = "translateY(-5px)";
        });

        card.addEventListener("mouseleave", () => {
            card.style.transform = "translateY(0)";
        });

    });

});