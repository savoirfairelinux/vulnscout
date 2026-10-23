import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import App from './App.tsx'
import { UnsavedGuardProvider } from './hooks/useUnsavedGuard'
import './index.css'

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <UnsavedGuardProvider>
        <App />
      </UnsavedGuardProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
