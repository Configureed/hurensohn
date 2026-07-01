import React from 'react';

const LoadingSpinner = () => {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="relative">
        <div className="w-16 h-16 border-4 border-primary/30 border-t-primary rounded-full animate-spin"></div>
        <p className="text-gray-400 mt-4 text-center">Loading...</p>
      </div>
    </div>
  );
};

export default LoadingSpinner;