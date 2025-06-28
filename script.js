let currentCardIndex = 0;
let isFlipped = false;

// DOM elements
const flashcard = document.getElementById('flashcard');
const questionText = document.getElementById('question-text');
const answerText = document.getElementById('answer-text');
const currentCardSpan = document.getElementById('current-card');
const totalCardsSpan = document.getElementById('total-cards');
const prevBtn = document.getElementById('prev-btn');
const flipBtn = document.getElementById('flip-btn');
const nextBtn = document.getElementById('next-btn');

// Initialize
function init() {
    totalCardsSpan.textContent = flashcards.length;
    loadCard(0);
    
    // Event listeners
    flipBtn.addEventListener('click', flipCard);
    prevBtn.addEventListener('click', previousCard);
    nextBtn.addEventListener('click', nextCard);
    flashcard.addEventListener('click', flipCard);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        switch(e.key) {
            case ' ':
                e.preventDefault();
                flipCard();
                break;
            case 'ArrowLeft':
                previousCard();
                break;
            case 'ArrowRight':
                nextCard();
                break;
        }
    });
}

function loadCard(index) {
    if (index < 0 || index >= flashcards.length) return;
    
    currentCardIndex = index;
    currentCardSpan.textContent = index + 1;
    
    const card = flashcards[index];
    questionText.textContent = card.question;
    answerText.innerHTML = formatAnswer(card.answer);
    
    // Reset flip state
    if (isFlipped) {
        flashcard.classList.remove('flipped');
        isFlipped = false;
    }
    
    // Update button states
    prevBtn.disabled = index === 0;
    nextBtn.disabled = index === flashcards.length - 1;
}

function formatAnswer(answer) {
    // Convert markdown-style code blocks to HTML
    answer = answer.replace(/```(\w+)?\n([\s\S]*?)```/g, (match, lang, code) => {
        return `<pre><code>${escapeHtml(code.trim())}</code></pre>`;
    });
    
    // Convert inline code
    answer = answer.replace(/`([^`]+)`/g, '<code>$1</code>');
    
    // Convert line breaks to <br> for better formatting
    answer = answer.split('\n').map(line => line.trim()).join('<br>');
    
    // Convert **bold** to <strong>
    answer = answer.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    
    return answer;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function flipCard() {
    isFlipped = !isFlipped;
    flashcard.classList.toggle('flipped');
}

function previousCard() {
    if (currentCardIndex > 0) {
        loadCard(currentCardIndex - 1);
    }
}

function nextCard() {
    if (currentCardIndex < flashcards.length - 1) {
        loadCard(currentCardIndex + 1);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', init);