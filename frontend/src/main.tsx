import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

// Initialize mock Wails runtime in development mode
if (import.meta.env.DEV) {
  import('./utils/mockData').then(({ initMockRuntime }) => {
    initMockRuntime()
  })
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
