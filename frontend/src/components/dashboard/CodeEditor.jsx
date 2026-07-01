import React, { useRef, useEffect } from 'react';

const CodeEditor = ({ value, onChange, height = '300px' }) => {
  const textareaRef = useRef(null);

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = 'auto';
      textareaRef.current.style.height = textareaRef.current.scrollHeight + 'px';
    }
  }, [value]);

  const handleChange = (e) => {
    onChange(e.target.value);
  };

  return (
    <div className="relative">
      <textarea
        ref={textareaRef}
        value={value}
        onChange={handleChange}
        style={{ height }}
        className="w-full bg-black/50 border border-white/10 rounded-xl p-4 text-sm font-mono text-green-400 placeholder-gray-600 focus:outline-none focus:border-primary transition-colors resize-none"
        spellCheck={false}
        placeholder="# Write your Python code here..."
      />
      <div className="absolute top-3 right-3 flex items-center space-x-2 text-xs text-gray-600">
        <span className="bg-white/5 px-2 py-1 rounded">Python</span>
        <span className="bg-white/5 px-2 py-1 rounded">{value.split('\n').length} lines</span>
      </div>
    </div>
  );
};

export default CodeEditor;