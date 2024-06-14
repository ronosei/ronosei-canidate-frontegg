import logo from './logo.svg';
import './App.css';
import { useAuth, useLoginWithRedirect, ContextHolder } from "@frontegg/react";
import { useEffect } from 'react';
import { AdminPortal } from '@frontegg/react'
import React from 'react';


function App() {

  const { user, isAuthenticated } = useAuth();
  const loginWithRedirect = useLoginWithRedirect();

  // Uncomment this to redirect to login automatically
   useEffect(() => {
    if (!isAuthenticated) {
   loginWithRedirect();
     }
   }, [isAuthenticated, loginWithRedirect]);

   //logout
  const logout = () => {
    const baseUrl = ContextHolder.getContext().baseUrl;
    window.location.href = `${baseUrl}/oauth/logout?post_logout_redirect_uri=${window.location}`;
  };

  //admin portal 
  const handleClick = () => {
    AdminPortal.show();
  };

  return (
    <div className="App">
      {isAuthenticated ? (
       <div>
        <div>
       <img src={user?.profilePictureUrl} alt={user?.name}/>
     </div>
      <div>
      <span>Logged in as: {user?.name}</span>
    </div>
    <div>
      <button onClick={() => handleClick() }>Setting</button>
    </div>
    <div>
      <button onClick={() => logout()}>Click to logout</button>
    </div>
    </div>
      ): (
        <div> 
        <button onclick={() => loginWithRedirect()}
        className="button">
        Click here to login
  </button>
  </div>
)}

</div>
  );
}

export default App;
