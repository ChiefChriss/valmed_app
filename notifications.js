// Live notification polling with SocketIO
function initNotificationPolling(initialCount, unreadCountUrl) {
  let lastCount = initialCount;

  function updateNotificationBadge(count) {
    const bellLink = document.querySelector('.nav-link .bi-bell');
    if (!bellLink) return;
    
    const bellParent = bellLink.parentElement;
    let badge = bellParent.querySelector('.badge');
    
    if (count > 0) {
      if (!badge) {
        // Create badge if it doesn't exist
        badge = document.createElement('span');
        badge.className = 'position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger';
        bellParent.appendChild(badge);
      }
      // Update badge text
      badge.textContent = count < 10 ? count : '9+';
      
      // Show browser notification if count increased
      if (count > lastCount && 'Notification' in window && Notification.permission === 'granted') {
        new Notification('Valdosta Medicine', {
          body: 'You have new notifications',
          icon: '/static/favicon.ico'
        });
      }
    } else {
      // Remove badge if count is 0
      if (badge) {
        badge.remove();
      }
    }
    
    lastCount = count;
  }

  // Initialize SocketIO connection
  const socket = io();
  
  socket.on('connect', function() {
    console.log('Connected to notification server');
  });
  
  socket.on('disconnect', function() {
    console.log('Disconnected from notification server');
  });
  
  // Function to update notification dropdown (make it globally accessible)
  window.updateNotificationDropdown = function() {
    const recentUrl = unreadCountUrl.replace('/unread_count', '/recent');
    fetch(recentUrl)
      .then(response => response.json())
      .then(data => {
        // Find the notification dropdown menu (the one near the bell icon)
        const bellLink = document.querySelector('.nav-link .bi-bell');
        if (!bellLink) return;
        const dropdown = bellLink.closest('.nav-item').querySelector('.dropdown-menu');
        if (!dropdown) return;
        
        // Find the divider after header
        const divider = dropdown.querySelector('.dropdown-divider');
        if (!divider) return;
        
        // Remove existing notification items (keep header and divider)
        const itemsToRemove = [];
        dropdown.querySelectorAll('li').forEach(li => {
          if (li !== divider && !li.querySelector('.dropdown-header') && !li.querySelector('a[href*="notifications"]')) {
            itemsToRemove.push(li);
          }
        });
        itemsToRemove.forEach(li => li.remove());
        
        // Add new notifications
        if (data.notifications && data.notifications.length > 0) {
          data.notifications.forEach(notif => {
            const li = document.createElement('li');
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = `/notifications/${notif.id}/mark_read`;
            form.className = 'notification-item';
            
            const button = document.createElement('button');
            button.className = `dropdown-item ${notif.is_read ? '' : 'bg-light'} py-2`;
            button.style.whiteSpace = 'normal';
            button.type = 'submit';
            
            // Icon based on type
            let iconClass = 'bi bi-bell text-primary';
            if (notif.type === 'task_assigned') iconClass = 'bi bi-person-check text-primary';
            else if (notif.type === 'status_changed') iconClass = 'bi bi-arrow-repeat text-info';
            else if (notif.type === 'comment_added') iconClass = 'bi bi-chat-left-text text-success';
            else if (notif.type === 'group_task') iconClass = 'bi bi-people text-warning';
            
            button.innerHTML = `
              <div class="d-flex">
                <div class="me-2">
                  <i class="${iconClass}"></i>
                </div>
                <div class="flex-grow-1">
                  <div class="fw-bold small">${notif.title}</div>
                  <div class="text-muted small">${notif.message}</div>
                  <div class="text-muted" style="font-size: 0.7rem;">${notif.created_at || ''}</div>
                </div>
                ${notif.is_read ? '' : '<div class="ms-2"><span class="badge bg-primary rounded-circle" style="width: 8px; height: 8px; padding: 0;"></span></div>'}
              </div>
            `;
            
            form.appendChild(button);
            li.appendChild(form);
            dropdown.insertBefore(li, divider.nextSibling);
          });
          
          // Add "View All" link if not present
          if (!dropdown.querySelector('a[href*="notifications"]')) {
            const viewAllLi = document.createElement('li');
            viewAllLi.innerHTML = '<hr class="dropdown-divider">';
            dropdown.appendChild(viewAllLi);
            
            const viewAllLink = document.createElement('li');
            viewAllLink.innerHTML = '<a class="dropdown-item text-center small text-primary" href="/notifications">View All Notifications</a>';
            dropdown.appendChild(viewAllLink);
          }
        } else {
          // Show "No notifications" if empty
          const noNotifLi = document.createElement('li');
          noNotifLi.className = 'text-center py-4 text-muted';
          noNotifLi.innerHTML = '<i class="bi bi-bell-slash display-6 opacity-25"></i><p class="small mt-2 mb-0">No notifications</p>';
          dropdown.insertBefore(noNotifLi, divider.nextSibling);
        }
      })
        .catch(error => console.error('Error fetching notifications:', error));
  };
  
  // Make function globally accessible
  window.updateNotificationDropdown = updateNotificationDropdown;

  // Listen for real-time notifications
  socket.on('new_notification', function(data) {
    console.log('New notification received:', data);
    
    // Update badge count
    if (data.unread_count !== undefined) {
      updateNotificationBadge(data.unread_count);
    } else if (data.count !== undefined) {
      updateNotificationBadge(data.count);
    } else {
      // Fallback: Fetch updated count if not included in event
      fetch(unreadCountUrl)
        .then(response => response.json())
        .then(data => {
          updateNotificationBadge(data.count);
        })
        .catch(error => console.error('Error fetching notification count:', error));
    }
    
    // Update dropdown
    updateNotificationDropdown();
    
    // Show browser notification
    if ('Notification' in window && Notification.permission === 'granted') {
      new Notification(data.title, {
        body: data.message,
        icon: '/static/favicon.ico'
      });
    }
  });
  
  // Fallback: Poll every 3 seconds (in case WebSocket fails)
  setInterval(function() {
    fetch(unreadCountUrl)
      .then(response => response.json())
      .then(data => {
        updateNotificationBadge(data.count);
      })
      .catch(error => console.error('Error fetching notifications:', error));
  }, 3000);

  // Request notification permission on first load
  if ('Notification' in window && Notification.permission === 'default') {
    Notification.requestPermission();
  }
  
  // Initialize badge with current count
  updateNotificationBadge(initialCount);
}

