/* Simple cache web service worker for PWAs */
let cacheName = 'WeatherClient-cache';

self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(cacheName).then(function(cache) {
      // Use self.registration.scope to find the base URL instead
      return cache.addAll(
        [ /* All resources that are fit to store */
          './index.html',
          './changes.html',
          './sw.js',
          './manifest.json',
          './locations.json',
          './js/localforage.min-1.7.3.js',
          './js/handlebars-v4.1.2.js',
          './js/morphdom-2.5.4.js',
          './css/bootstrap-3.4.1.min.css',
          './app.css'
          // '/offline.html'
        ]
      );
    })
  );
});

/* Serve everything from the cache */
/*
self.addEventListener('fetch', function(event) {
  event.respondWith(caches.match(event.request));
});
*/

function fetchAndCache(event) {
    console.log("Returning network request via fetch() for " + event.request.url);
    //return fetch(event.request);

    // Fetch data online, cache locally
    return caches.open(cacheName).then(function(cache) {
        return fetch(event.request).then(function(response) {
            if( response ) {
                //console.log("Stored asset " + event.request.url);
                cache.put(event.request, response.clone());

                return response;
            } else {
                console.log("Fetching " + event.request.url + " failed...");
                return undefined;
            };
        });
    })
}

self.addEventListener('fetch', function(event) {
  event.respondWith(
    // Try the cache
    caches.match(event.request).then(function(response) {
      // Try the cache first
      //console.log(response);
      if( response !== undefined) {
          //console.log("Got a valid response from cache for " + event.request.url);
          return response;
      };

      // Never store our API calls
      if( event.request.url.match(/\/forecast$/)) {
          //console.log("API call to "+ + event.request.url);
          return fetch(event.request);
      };

      // Fall back to network
      //console.log("Falling back to the network");
      return fetchAndCache(event);

      // Inform the client that they should update their stuff
      /*
           client.postMessage({
             msg: "Hey I just got a fetch from you!",
             url: event.request.url
           });
      */
      console.log("Should never get here");

    }).catch(function(e) {
      // If both fail, show a generic fallback:
      console.log("Some error occurred",e);
      return caches.match('/offline.html');
      // However, in reality you'd have many different
      // fallbacks, depending on URL & headers.
      // Eg, a fallback silhouette image for avatars.
    })
  );
});

/* Evict outdated stuff resp. update our new cache */
self.addEventListener('activate', function(event) {
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      console.log("Re-caching assets");
      return Promise.all(
        cacheNames.filter(function(cacheName) {
          // Return true if you want to remove this cache,
          // but remember that caches are shared across
          // the whole origin
          return 1

        }).map(function(cacheName) {
          return caches.delete(cacheName);
        })
      );
    })
  );
});
