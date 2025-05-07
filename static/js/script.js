document.addEventListener('DOMContentLoaded', function() {
    // File upload functionality
    const fileInputs = document.querySelectorAll('.file-upload-container input[type="file"]');
    
    fileInputs.forEach(input => {
        const container = input.parentElement;
        
        container.addEventListener('click', () => {
            input.click();
        });
        
        input.addEventListener('change', () => {
            if (input.files.length > 0) {
                const fileNameDisplay = container.querySelector('.file-name');
                if (fileNameDisplay) {
                    fileNameDisplay.textContent = input.files[0].name;
                    container.classList.add('file-selected');
                }
            }
        });
    });
    
    // Show loading indicator when forms are submitted
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function() {
            const submitButton = this.querySelector('.btn-submit');
            if (submitButton) {
                submitButton.disabled = true;
                submitButton.textContent = 'Processing...';
            }
            
            const resultsContainer = document.querySelector('.results-container');
            if (resultsContainer) {
                resultsContainer.classList.add('loading');
            } else {
                const newLoader = document.createElement('div');
                newLoader.classList.add('loader');
                this.appendChild(newLoader);
            }
        });
    });
    
    // Hashing tool tabs
    const hashInputTabs = document.querySelectorAll('.input-method-tab');
    const hashInputMethods = document.querySelectorAll('.input-method');
    
    hashInputTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const target = this.getAttribute('data-target');
            
            // Update active tab
            hashInputTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            
            // Show target input method
            hashInputMethods.forEach(method => {
                if (method.id === target) {
                    method.classList.add('active');
                } else {
                    method.classList.remove('active');
                }
            });
        });
    });
    
    // Hash algorithm selection
    const hashOptions = document.querySelectorAll('.hash-option');
    
    hashOptions.forEach(option => {
        option.addEventListener('click', function() {
            const algoInput = document.querySelector('input[name="algorithm"]');
            
            // Update UI
            hashOptions.forEach(opt => opt.classList.remove('active'));
            this.classList.add('active');
            
            // Set algorithm value
            if (algoInput) {
                algoInput.value = this.getAttribute('data-algo');
            }
        });
    });
    
    // Custom port range toggle in Network Utilities
    const portRangeSelect = document.getElementById('port-range');
    const customPortRange = document.getElementById('custom-port-range');
    
    if (portRangeSelect && customPortRange) {
        portRangeSelect.addEventListener('change', function() {
            if (this.value === 'custom') {
                customPortRange.classList.remove('hidden');
            } else {
                customPortRange.classList.add('hidden');
            }
        });
    }
    
    // Tool tabs in Network Utilities
    const toolTabs = document.querySelectorAll('.tool-tab');
    const toolContents = document.querySelectorAll('.tool-content');
    
    toolTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const target = this.getAttribute('data-tool');
            
            // Update active tab
            toolTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            
            // Show target tool
            toolContents.forEach(content => {
                if (content.id === target + '-tool') {
                    content.classList.remove('hidden');
                } else {
                    content.classList.add('hidden');
                }
            });
        });
    });
    
    // Category tabs in Education
    const categoryTabs = document.querySelectorAll('.category-tab');
    const categoryContents = document.querySelectorAll('.category-content');
    
    categoryTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const target = this.getAttribute('data-category');
            
            // Update active tab
            categoryTabs.forEach(t => t.classList.remove('active'));
            this.classList.add('active');
            
            // Show target content
            categoryContents.forEach(content => {
                if (content.id === target + '-content') {
                    content.classList.remove('hidden');
                } else {
                    content.classList.add('hidden');
                }
            });
        });
    });
    
    // Automatically scroll to results if they exist
    const resultsContainer = document.querySelector('.results-container');
    if (resultsContainer) {
        setTimeout(() => {
            resultsContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }, 100);
    }
});