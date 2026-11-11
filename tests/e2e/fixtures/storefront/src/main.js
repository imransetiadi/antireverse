import { addToCart, applyCode, createCart, renderSummary, summary } from "./storefront.js";

let cart = addToCart(addToCart(createCart(), "hoodie-zip"), "tee-organic", 2);
cart = applyCode(cart, "bundle15");
document.getElementById("cart").textContent = renderSummary(summary(cart, "DE"));
document.body.dataset.ready = "1";
