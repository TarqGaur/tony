window.addEventListener('DOMContentLoaded', () => {
    // 1. Your pool of background videos
    const videos = [
        'ui/main1.mp4',
        'ui/main2.mp4',
        'ui/main3.mp4',
        'ui/main4.mp4'
    ];

    // 2. Pick a random video upfront
    const randomIndex = Math.floor(Math.random() * videos.length);
    const selectedVideo = videos[randomIndex];

    // 3. Try to find EITHER video element on the current page  
    // This looks for #video, and if it doesn't find it, looks for #video2
    const videoElement = document.getElementById('video') ;

    // 4. Only run the code if one of the video elements actually exists on this page
    if (videoElement) {
        const sourceElement = document.createElement('source');
        sourceElement.src = selectedVideo;
        sourceElement.type = 'video/mp4';

        videoElement.appendChild(sourceElement);
        videoElement.load();
        
        console.log(`Successfully loaded random background: ${selectedVideo}`);
    }
});